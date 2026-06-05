from pathlib import Path

from pyspark.sql import SparkSession
from pyspark.sql.functions import col

GOLD_DIR = Path("data/gold")

def get_spark():
    return (
        SparkSession.builder
        .appName("security-copilot-queries")
        .master("local[*]")
        .getOrCreate()
    )

def main():
    spark = get_spark()

    findings = spark.read.parquet(str(GOLD_DIR / "security_findings_enriched"))
    user_risk = spark.read.parquet(str(GOLD_DIR / "user_risk_summary"))
    ip_reputation = spark.read.parquet(str(GOLD_DIR / "ip_reputation_summary"))
    timeline = spark.read.parquet(str(GOLD_DIR / "alert_timeline"))

    print("\n=== High Severity Findings ===")
    findings.filter(col("severity_label") == "high").show(10, truncate=False)

    print("\n=== Highest Risk Users ===")
    user_risk.orderBy(col("risk_score").desc()).show(10, truncate=False)

    print("\n=== Known Bad IP Activity ===")
    ip_reputation.filter(col("known_bad_hits") > 0).orderBy(col("known_bad_hits").desc()).show(10, truncate=False)

    print("\n=== High-Risk Timeline Events ===")
    timeline.filter(col("risk_level") == "high").show(20, truncate=False)

    print("\n=== Investigation Timeline: jsmith ===")
    timeline.filter(col("user_name") == "jsmith").orderBy("event_timestamp").show(50, truncate=False)

    print("\n=== Investigation Timeline: admin.user ===")
    timeline.filter(col("user_name") == "admin.user").orderBy("event_timestamp").show(50, truncate=False)

    print("\n=== Investigation Timeline: svc-ci-cd ===")
    timeline.filter(col("user_name") == "svc-ci-cd").orderBy("event_timestamp").show(50, truncate=False)

    print("\n=== Known Bad IP Timeline ===")
    timeline.filter(col("is_known_bad_ip") == True).orderBy("event_timestamp").show(100, truncate=False)

    spark.stop()

if __name__ == "__main__":
    main()