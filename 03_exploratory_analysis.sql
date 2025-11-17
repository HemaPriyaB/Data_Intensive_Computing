USE CATALOG workspace;
USE SCHEMA default;

-- 1.1 Row counts across Bronze & Silver
SELECT 'cve_bronze_records'    AS table_name, COUNT(*) AS row_count FROM cve_bronze_records
UNION ALL
SELECT 'cve_core'              AS table_name, COUNT(*) AS row_count FROM cve_core
UNION ALL
SELECT 'cve_affected_products' AS table_name, COUNT(*) AS row_count FROM cve_affected_products;

-- 1.2 Preview Silver tables 
SELECT * FROM cve_core LIMIT 10;
SELECT * FROM cve_affected_products LIMIT 10;


-- 2. TEMPORAL ANALYSIS (2024 CVE TREND)
-- 2.1 Monthly CVE counts for 2024
SELECT
  date_trunc('month', published_date) AS month_start,
  COUNT(*) AS cve_count
FROM cve_core
WHERE year(published_date) = 2024
GROUP BY date_trunc('month', published_date)
ORDER BY month_start;

-- 2.2 Weekly CVE counts for 2024
SELECT
  date_trunc('week', published_date) AS week_start,
  COUNT(*) AS cve_count
FROM cve_core
WHERE year(published_date) = 2024
GROUP BY date_trunc('week', published_date)
ORDER BY week_start;

-- 2.3 Time between publish and last_modified days
SELECT
  APPROX_PERCENTILE(DATEDIFF(last_modified_date, published_date), 0.5) AS median_days_to_update,
  APPROX_PERCENTILE(DATEDIFF(last_modified_date, published_date), 0.9) AS p90_days_to_update
FROM cve_core
WHERE published_date IS NOT NULL
  AND last_modified_date IS NOT NULL;


-- 3. RISK / SEVERITY DISTRIBUTION (CVSS)
-- 3.1 Severity buckets and percentages
WITH scored AS (
  SELECT
    cve_id,
    cvss_score,
    CASE
      WHEN cvss_score >= 9.0 THEN 'Critical'
      WHEN cvss_score >= 7.0 THEN 'High'
      WHEN cvss_score >= 4.0 THEN 'Medium'
      WHEN cvss_score >= 0.1 THEN 'Low'
      ELSE 'Unscored'
    END AS severity_bucket
  FROM cve_core
)
SELECT
  severity_bucket,
  COUNT(*) AS cve_count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS pct_of_total
FROM scored
GROUP BY severity_bucket
ORDER BY
  CASE severity_bucket
    WHEN 'Critical' THEN 1
    WHEN 'High'     THEN 2
    WHEN 'Medium'   THEN 3
    WHEN 'Low'      THEN 4
    ELSE 5
  END;

-- 3.2 Count of CVEs with no CVSS score
SELECT
  COUNT(*) AS unscored_cves
FROM cve_core
WHERE cvss_score IS NULL;


-- 4. VENDOR INTELLIGENCE
-- 4.1 Top 25 vendors by distinct CVE count
SELECT
  vendor,
  COUNT(DISTINCT cve_id) AS cve_count
FROM cve_affected_products
GROUP BY vendor
ORDER BY cve_count DESC
LIMIT 25;

-- 4.2 Vendor severity profile: Critical / High / Medium / Low per vendor
WITH severity AS (
  SELECT
    cve_id,
    CASE
      WHEN cvss_score >= 9.0 THEN 'Critical'
      WHEN cvss_score >= 7.0 THEN 'High'
      WHEN cvss_score >= 4.0 THEN 'Medium'
      WHEN cvss_score >= 0.1 THEN 'Low'
      ELSE 'Unscored'
    END AS severity_bucket
  FROM cve_core
),
vendor_join AS (
  SELECT
    a.vendor,
    s.severity_bucket,
    a.cve_id
  FROM cve_affected_products a
  JOIN severity s
    ON a.cve_id = s.cve_id
)
SELECT
  vendor,
  severity_bucket,
  COUNT(DISTINCT cve_id) AS cve_count
FROM vendor_join
GROUP BY vendor, severity_bucket
ORDER BY vendor,
  CASE severity_bucket
    WHEN 'Critical' THEN 1
    WHEN 'High'     THEN 2
    WHEN 'Medium'   THEN 3
    WHEN 'Low'      THEN 4
    ELSE 5
  END;

-- 4.3 Vendor risk summary: total CVEs, avg CVSS, number of High+Critical CVEs
WITH joined AS (
  SELECT
    a.vendor,
    c.cve_id,
    c.cvss_score
  FROM cve_affected_products a
  JOIN cve_core c
    ON a.cve_id = c.cve_id
)
SELECT
  vendor,
  COUNT(DISTINCT cve_id) AS total_cves,
  ROUND(AVG(cvss_score), 2) AS avg_cvss_score,
  COUNT(DISTINCT CASE WHEN cvss_score >= 7.0 THEN cve_id END) AS high_or_critical_cves
FROM joined
GROUP BY vendor
ORDER BY total_cves DESC
LIMIT 25;

-- 5. "TOP N" RISK FOCUS
-- 5.1 Top 50 highest-risk CVEs by CVSS score
SELECT
  cve_id,
  published_date,
  cvss_score,
  cvss_vector,
  description
FROM cve_core
WHERE cvss_score IS NOT NULL
ORDER BY cvss_score DESC, published_date DESC
LIMIT 50;

-- 5.2 Top risky products for a specific vendor
WITH joined AS (
  SELECT
    a.vendor,
    a.product,
    c.cve_id,
    c.cvss_score
  FROM cve_affected_products a
  JOIN cve_core c
    ON a.cve_id = c.cve_id
  WHERE lower(a.vendor) = 'microsoft'
)
SELECT
  product,
  COUNT(DISTINCT cve_id) AS total_cves,
  ROUND(AVG(cvss_score), 2) AS avg_cvss_score,
  COUNT(DISTINCT CASE WHEN cvss_score >= 7.0 THEN cve_id END) AS high_or_critical_cves
FROM joined
GROUP BY product
ORDER BY total_cves DESC
LIMIT 25;

-- 6. OPTIONAL: REUSABLE VIEWS (FOR GOLD / DASHBOARDS)
-- 6.1 Per-CVE severity categorization view
CREATE OR REPLACE VIEW cve_severity_view AS
SELECT
  cve_id,
  cvss_score,
  CASE
    WHEN cvss_score >= 9.0 THEN 'Critical'
    WHEN cvss_score >= 7.0 THEN 'High'
    WHEN cvss_score >= 4.0 THEN 'Medium'
    WHEN cvss_score >= 0.1 THEN 'Low'
    ELSE 'Unscored'
  END AS severity_bucket
FROM cve_core;

-- 6.2 Vendor-level risk summary view
CREATE OR REPLACE VIEW vendor_risk_summary AS
WITH joined AS (
  SELECT
    a.vendor,
    c.cve_id,
    c.cvss_score
  FROM cve_affected_products a
  JOIN cve_core c
    ON a.cve_id = c.cve_id
)
SELECT
  vendor,
  COUNT(DISTINCT cve_id) AS total_cves,
  ROUND(AVG(cvss_score), 2) AS avg_cvss_score
FROM joined
GROUP BY vendor;

-- 6.3 Overall concentration: % of CVEs contributed by top 10 vendors
WITH vendor_counts AS (
  SELECT
    vendor,
    COUNT(DISTINCT cve_id) AS total_cves
  FROM cve_affected_products
  GROUP BY vendor
),
ranked AS (
  SELECT
    vendor,
    total_cves,
    RANK() OVER (ORDER BY total_cves DESC) AS vendor_rank
  FROM vendor_counts
),
top10 AS (
  SELECT SUM(total_cves) AS top10_cves
  FROM ranked
  WHERE vendor_rank <= 10
),
overall AS (
  SELECT SUM(total_cves) AS total_cves
  FROM ranked
)
SELECT
  o.total_cves,
  t.top10_cves,
  ROUND(100.0 * t.top10_cves / o.total_cves, 2) AS pct_cves_in_top10_vendors
FROM overall o CROSS JOIN top10 t;
