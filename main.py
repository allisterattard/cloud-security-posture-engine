import importlib
import concurrent.futures
import config
from intelligence import create_security_graph
from core.reporter import generate_soc_markdown_report
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
import os

load_dotenv()
tenant_id = os.getenv("AZURE_TENANT_ID")
client_id = os.getenv("AZURE_CLIENT_ID")
client_secret = os.getenv("AZURE_CLIENT_SECRET")

credential = ClientSecretCredential(
    tenant_id=tenant_id,
    client_id=client_id,
    client_secret=client_secret
)

SUB_ID = os.getenv("AZURE_SUBSCRIPTION_ID")

def execute_plugin(plugin_name):
    """Dynamically imports and executes a single scanner plugin."""
    try: 
        module = importlib.import_module(f"plugins.{plugin_name}")

        findings = module.run_scan(credential, SUB_ID)
        return findings
    except Exception as e:
        print(f"  [!] Error running plugin {plugin_name}: {e}")
        return []
    
def main():
    print("=" * 60)
    print("🔍 [Step 1/3] Starting Azure Security Posture Discovery...")
    print("=" * 60)

    all_findings = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(execute_plugin, p_name): p_name
            for p_name in config.ENABLED_PLUGINS
        }
        for future in concurrent.futures.as_completed(futures):
            plugin_results = future.result()
            if plugin_results:
                all_findings.extend(plugin_results)
    
    print(f"\n✅ Audit Complete! Identified {len(all_findings)} raw issue(s)")
    if not all_findings:
        print("🎉 No Security drift detected: Your Azure environment is compliant!")
        return

    print("=" * 60)
    print("🤖 [Step 2/3] Invoking LangGraph AI Engine (Risk Analyst + Fix Generator)...")
    print("=" * 60)

    app = create_security_graph()
    initial_state = {
        "subscription_id": SUB_ID,
        "findings": all_findings,
        "risk_report": {},
        "remediation_plan": {}
    }

    final_state = app.invoke(initial_state)

    print("=" * 60)
    print("📄 [Step 3/3] Generating SOC Remediation Report...")
    print("=" * 60)

    output_markdown_file = "azure_security_report.md"
    generate_soc_markdown_report(final_state, output_markdown_file)

    print(f"\n🚀 Pipeline finished successfully! Report saved to: {output_markdown_file}\n")

if __name__ == "__main__":
    main()