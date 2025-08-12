import sys
import hashlib
import pandas as pd
from datetime import datetime

from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from awsglue.dynamicframe import DynamicFrame

def main():
    """
    Main ETL logic wrapped in a function.
    This function is called by AWS Glue and can also be called for local testing.
    """
    # ==============================================================================
    # 1. INITIALIZATION & ARGUMENT PARSING
    # ==============================================================================
    # In AWS Glue, the real arguments are passed here.
    # For local testing, mock arguments are passed from the __main__ block.
    args = getResolvedOptions(sys.argv, [
        'JOB_NAME',
        'S3_INPUT_SALES_PATH',
        'S3_OUTPUT_PROCESSED_PATH',
        'S3_ERROR_PATH',
        'JDBC_CONNECTION_NAME'
    ])

    sc = SparkContext()
    glueContext = GlueContext(sc)
    spark = glueContext.spark_session
    job = Job(glueContext)
    job.init(args['JOB_NAME'], args)

    # ==============================================================================
    # 2. EXTRACTION (Reading data from sources)
    # ==============================================================================
    print("Starting data extraction...")

    sales_dyf = glueContext.create_dynamic_frame.from_options(
        connection_type="s3",
        connection_options={"paths": [args['S3_INPUT_SALES_PATH']]},
        format="csv",
        format_options={"withHeader": True, "inferSchema": True},
        transformation_ctx="sales_dyf"
    )
    print(f"Read {sales_dyf.count()} sales records from S3.")

    customers_dyf = glueContext.create_dynamic_frame.from_options(
        connection_type="mysql",
        connection_options={
            "useConnectionProperties": "true",
            "connectionName": args['JDBC_CONNECTION_NAME'],
            "dbtable": "public.customers"
        },
        transformation_ctx="customers_dyf"
    )
    print(f"Read {customers_dyf.count()} customer records from JDBC source.")

    # ==============================================================================
    # 3. TRANSFORMATION: Data Quality Checks
    # ==============================================================================
    print("Performing data quality checks...")

    def has_valid_quantity(rec):
        return rec["quantity"] is not None and isinstance(rec["quantity"], int) and rec["quantity"] > 0

    split_dyf = SplitRows.apply(
        frame=sales_dyf,
        comparison_dict={"quantity": has_valid_quantity},
        name="has_valid_quantity",
        transformation_ctx="split_dyf"
    )

    good_sales_dyf = split_dyf.select("has_valid_quantity_yes")
    bad_sales_dyf = split_dyf.select("has_valid_quantity_no")

    error_count = bad_sales_dyf.count()
    if error_count > 0:
        print(f"Found {error_count} records failing data quality. Writing to error path...")
        glueContext.write_dynamic_frame.from_options(
            frame=bad_sales_dyf,
            connection_type="s3",
            connection_options={"path": args['S3_ERROR_PATH']},
            format="json",
            transformation_ctx="write_bad_records"
        )
    
    print(f"{good_sales_dyf.count()} sales records passed data quality checks.")

    # ==============================================================================
    # 4. TRANSFORMATION: Cleaning and Joining
    # ==============================================================================
    print("Cleaning and enriching data...")

    sales_cleaned_dyf = ApplyMapping.apply(
        frame=good_sales_dyf,
        mappings=[
            ("transaction_id", "string", "transaction_id", "string"),
            ("product_id", "string", "product_id", "string"),
            ("customer_id", "string", "customer_id", "long"),
            ("quantity", "int", "quantity", "int"),
            ("price", "double", "sale_price", "double"),
            ("transaction_date", "string", "transaction_ts", "timestamp")
        ],
        transformation_ctx="sales_cleaned_dyf"
    )

    customers_cleaned_dyf = ApplyMapping.apply(
        frame=customers_dyf,
        mappings=[
            ("customer_id", "long", "customer_id", "long"),
            ("full_name", "string", "customer_name", "string"),
            ("email", "string", "email", "string"),
            ("state", "string", "customer_state", "string"),
            ("signup_date", "timestamp", "signup_ts", "timestamp")
        ],
        transformation_ctx="customers_cleaned_dyf"
    )

    enriched_dyf = Join.apply(
        sales_cleaned_dyf,
        customers_cleaned_dyf,
        'customer_id',
        'customer_id',
        transformation_ctx="enriched_dyf"
    )
    print(f"Enriched data frame has {enriched_dyf.count()} records after join.")

    # ==============================================================================
    # 5. TRANSFORMATION: Advanced Logic with Pandas
    # ==============================================================================
    print("Applying advanced transformations using Pandas...")

    enriched_pandas_df = enriched_dyf.toDF().toPandas()

    def mask_string(value: str) -> str:
        if not isinstance(value, str):
            return None
        return hashlib.sha256(value.encode()).hexdigest()

    def pandas_feature_engineering(df: pd.DataFrame) -> pd.DataFrame:
        df['customer_tenure_days'] = (df['transaction_ts'] - df['signup_ts']).dt.days
        df['email_masked'] = df['email'].apply(mask_string)
        df = df.drop(columns=['email', 'signup_ts'])
        df['processed_at'] = datetime.utcnow()
        return df

    processed_pandas_df = pandas_feature_engineering(enriched_pandas_df)
    
    spark_df = spark.createDataFrame(processed_pandas_df)
    final_dyf = DynamicFrame.fromDF(spark_df, glueContext, "final_dyf")
    print("Pandas transformations complete.")

    # ==============================================================================
    # 6. LOAD (Writing final data to S3)
    # ==============================================================================
    print("Writing final processed data to S3...")

    glueContext.write_dynamic_frame.from_options(
        frame=final_dyf,
        connection_type="s3",
        connection_options={
            "path": args['S3_OUTPUT_PROCESSED_PATH'],
            "partitionKeys": ["customer_state", "transaction_ts"]
        },
        format="parquet",
        transformation_ctx="write_final_data"
    )
    
    job.commit()

# ==============================================================================
# SCRIPT ENTRY POINT
# ==============================================================================
if __name__ == '__main__':
    # This block is for LOCAL TESTING ONLY. It will NOT run in the AWS Glue environment.
    print("Running script locally...")
    
    # To run locally, you must mock the arguments that are normally passed by AWS Glue
    # You also need to have local test data at these paths.
    sys.argv.extend([
        '--JOB_NAME', 'LocalTestJob',
        '--S3_INPUT_SALES_PATH', './local_data/input/sales/',
        '--S3_OUTPUT_PROCESSED_PATH', './local_data/output/processed/',
        '--S3_ERROR_PATH', './local_data/output/error/',
        '--JDBC_CONNECTION_NAME', 'my-local-rds-connection' # NOTE: This part is hard to test locally
    ])
    
    # Call the main logic function
    main()