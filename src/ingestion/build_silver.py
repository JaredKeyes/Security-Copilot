from pathlib import Path

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, to_timestamp, when

BRONZE_DIR = Path("data/bronze")
SILVER_DIR = Path("data/silver")

def get_spark():
    return (
        SparkSession.builder
        .appname("security-copilot-silver")
        .master("local[*]")
        .getOrCreate()
    )

def main():
    spark = get_spark()

    SILVER_DIR.mkdir(parents=True, exist_ok=True)

    cloudtrail = spark.read.parquet(str(BRONZE_DIR / "cloudtrail_events"))
    guardduty = spark.read.parquet(str(BRONZE_DIR / "guardduty_findings"))
    iam_users = spark.read.parquet(str(BRONZE_DIR / "iam_users"))
    threat_intel = spark.read.parquet(str(BRONZE_DIR / "threat_intel"))

    cloudtrail_clean = (
        cloudtrail
        .withColumn("event_timestamp", to_timestamp(col("created_at")))
        .withColumn(
            "severity_label",
            when(col("severity") >= 7.0, "high")
            .when(col("severity") >= 4.0, "medium")
            .otherwise("low")
        )
    )

    cloudtrail_enriched = (
        cloudtrail_clean
        .join(
            threat_intel,
            cloudtrail_clean.source_ip_address == threat_intel.ip_address,
            "left"
        )
    )