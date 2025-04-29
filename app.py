import os
import kustoQuery
import apis
from azure.kusto.data import KustoClient
from azure.kusto.data.exceptions import KustoServiceError
from azure.kusto.data.helpers import dataframe_from_result_table

from flask import (Flask, redirect, render_template, request,
                   send_from_directory, url_for)

app = Flask(__name__)


@app.route('/')
def index():
   print('Request for index page received')
   return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/execute_prompt', methods=['POST'])
def execute_prompt():
   user_input = request.form.get('prompt')

   if user_input:
        print('Prompt=%s' % user_input)
        response = apis.call_openai(apis.system_prompt, user_input)
        # Printing the result
        print(response)
        # print("Kusto Query App is starting...")

        app = kustoQuery.KustoQueryApp()
        app.load_configs(app.CONFIG_FILE_NAME)

        # if app.config.authentication_mode == "UserPrompt":
        #     app.wait_for_user_to_proceed("You will be prompted for credentials during this script. Please return to the console after authenticating.")

        kusto_connection_string = apis.Utils.Authentication.generate_connection_string(app.config.kusto_uri, app.config.authentication_mode)
        print(f"Using cluster URI: {app.config.kusto_uri}")

        if not kusto_connection_string:
            apis.Utils.error_handler("Connection String error. Please validate your configuration file.")
        else:
            with KustoClient(kusto_connection_string) as kusto_client:
                df = app.query_table(kusto_client, app.config.database_name, app.config.table_name, response)

        print("\nKusto Query App done")

        return render_template('response.html', output = df.to_string(index=False))
   else:
        print('Request received without any prompt from the user or blank prompt -- redirecting')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()
