
---

# How to Run This Project

## Prerequisites
- Databricks Workspace  
- Unity Catalog enabled  
- Read access to DBFS/Volumes  

## Steps to Execute
1. Import all notebooks and SQL files into Databricks.
2. Run the **Bronze notebook** to ingest raw CVE JSON into Delta.
3. Run the **Silver notebook** to build normalized relational tables.
4. Run the **SQL Analysis** to generate insights, dashboards, and validations.

---

# What This Project Demonstrates
- Medallion Architecture implementation on Databricks  
- JSON ingestion and schema normalization techniques  
- Flattening and exploding nested arrays  
- CVSS scoring extraction and unification  
- End-to-end cybersecurity analytics workflow  
- SQL-based risk intelligence reporting  

---

# Key Learning Outcomes
By completing this project, you demonstrate skills in:
- Databricks Delta Lake architecture  
- SQL analytics on cybersecurity datasets  
- Data engineering pipeline development  
- Normalizing deeply nested JSON structures  
- Vendor and product-level vulnerability analysis  
- Building reproducible and production-ready workflows  

---
