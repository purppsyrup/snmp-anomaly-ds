from streamlit.web import cli
import sys

if __name__ == "__main__":
  #script_path = "/etc/xgb_nids/dash-0.1.03r5.py"
    # sys.argv = ["streamlit", "run", script_path]
  cli.main_run(["dash-0.1.03r5.py"])
