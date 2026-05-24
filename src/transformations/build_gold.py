from pathlib import Path

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count max as spark_max, sum as spark_sum, when

SILVER_DIR = Path("data/silver")
GOLD_DIR = Path("data/gold")

def get_spark():
    return (
        SparkSession.builder
        .appName("security-copilot-gold")
        .master("local[*]")
        .getOrCreate()
    )

def main():
    spark = get_spark()

    GOLD_DIR.mkdir(parents=True, exist_ok=True)

    cloudtrail = spark.read.parquet(str(SILVER_DIR / "cloudtrail_enriched"))
    guardduty = spark.read.parquet(str(SILVER_DIR / "guardduty_clean"))
    iam_users = spark.read.parquet(str(SILVER_DIR / "iam_users_clean"))

    security_findings_enriched = (
        guardduty
        .join(
            cloudtrail,
            guardduty.related_event_id == cloudtrail.event_id,
            "left"
        )
    )