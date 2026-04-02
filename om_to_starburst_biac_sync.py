from airflow.decorators import dag, task
from airflow.providers.http.hooks.http import HttpHook
from datetime import datetime, timedelta
import json

# Configuration Constants
TARGET_TAG_FQN = "PII.Sensitive"
TARGET_ROLE = "analyst_masked_role"
MASKING_EXPRESSION = "to_hex(sha256(to_utf8(cast({column} as varchar))))"

default_args = {
    'owner': 'data_governance',
    'depends_on_past': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=2),
}

@dag(
    default_args=default_args,
    schedule_interval='@hourly',
    start_date=datetime(2026, 3, 1),
    catchup=False,
    tags=['governance', 'openmetadata', 'starburst', 'biac'],
)
def sync_om_tags_to_starburst_biac_rest():

    @task()
    def fetch_om_state() -> list:
        """Queries OM ElasticSearch for tables containing the target tag."""
        http_hook = HttpHook(http_conn_id='openmetadata_rest_api', method='GET')
        endpoint = f"/api/v1/search/query?q=tags.tagFQN:\"{TARGET_TAG_FQN}\"&index=table_search_index&size=1000"
        
        response = http_hook.run(endpoint)
        data = json.loads(response.text)
        
        om_columns = set()
        for hit in data.get('hits', {}).get('hits', []):
            source = hit.get('_source', {})
            catalog = source.get('database', {}).get('name')
            schema = source.get('databaseSchema', {}).get('name')
            table = source.get('name')
            
            for col in source.get('columns', []):
                col_tags = [t.get('tagFQN') for t in col.get('tags', [])]
                if TARGET_TAG_FQN in col_tags:
                    om_columns.add(f"{catalog}.{schema}.{table}.{col.get('name')}")
                    
        return list(om_columns)

    @task()
    def fetch_starburst_state() -> list:
        """Queries Starburst BIAC API for current masks assigned to the target role."""
        http_hook = HttpHook(http_conn_id='starburst_rest_api', method='GET')
        endpoint = f"/api/v1/data-policies/masks?role={TARGET_ROLE}"
        
        try:
            response = http_hook.run(endpoint)
            rules = json.loads(response.text)
            # Extracts the fully qualified column names currently masked
            sb_columns = {rule['columnFqn'] for rule in rules}
        except Exception as e:
            print(f"No existing masks found or API error: {e}")
            sb_columns = set()
            
        return list(sb_columns)

    @task()
    def reconcile_masks(om_state_list: list, sb_state_list: list):
        """Calculates the diff and executes POST/DELETE requests against Starburst API."""
        om_state = set(om_state_list)
        sb_state = set(sb_state_list)
        
        to_add = om_state - sb_state
        to_remove = sb_state - om_state
        
        if not to_add and not to_remove:
            print("States are in sync. No action required.")
            return

        print(f"Columns to mask: {to_add}")
        print(f"Columns to unmask: {to_remove}")

        # Extract the underlying requests.Session from the Airflow Hook
        http_hook = HttpHook(http_conn_id='starburst_rest_api')
        session = http_hook.get_conn()
        url_endpoint = f"{http_hook.base_url}/api/v1/data-policies/masks"
        
        # 1. Remove revoked tags
        for column in to_remove:
            payload = {
                "role": TARGET_ROLE,
                "columnFqn": column
            }
            print(f"Revoking mask for {column}")
            response = session.delete(url_endpoint, json=payload)
            response.raise_for_status()
            
        # 2. Add new masks
        for column in to_add:
            # Extract just the column name for the SQL expression
            col_name = column.split('.')[-1]
            sql_expression = MASKING_EXPRESSION.replace("{column}", col_name)
            
            payload = {
                "role": TARGET_ROLE,
                "columnFqn": column,
                "expression": sql_expression
            }
            print(f"Applying mask for {column}")
            response = session.post(url_endpoint, json=payload)
            response.raise_for_status()

    # Define the execution graph
    om_data = fetch_om_state()
    sb_data = fetch_starburst_state()
    reconcile_masks(om_data, sb_data)

# Instantiate the DAG
dag_instance = sync_om_tags_to_starburst_biac_rest()