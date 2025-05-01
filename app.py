import os
import kustoQuery
import apis
from azure.kusto.data import KustoClient
import insights
import markdown

from flask import (Flask, redirect, render_template, request,
                   send_from_directory, url_for)

app = Flask(__name__)


@app.route('/')
def index():
   print('Request received from the index page')
   return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/execute_prompt', methods=['POST'])
def execute_prompt():
   user_input = request.form.get('prompt')

   if user_input:
        print('Received Prompt from User:')
        print(user_input)
        print('Calling OpenAI API to generate Kusto Query...')
        kql = apis.call_openai(apis.system_prompt, user_input)
        print('Received KQL in response from OpenAI API:')
        print(kql)
        print("Kusto Query App is starting...")
        app = kustoQuery.KustoQueryApp()
        app.load_configs(app.CONFIG_FILE_NAME)

        # if app.config.authentication_mode == "UserPrompt":
        #     app.wait_for_user_to_proceed("You will be prompted for credentials during this script. Please return to the console after authenticating.")
        print('Generating Kusto database connection string using authentication mode: %s' % app.config.authentication_mode)
        kusto_connection_string = apis.Utils.Authentication.generate_connection_string(app.config.kusto_uri, app.config.authentication_mode)
        print(f"ADX cluster URI: {app.config.kusto_uri}")

        if not kusto_connection_string:
            apis.Utils.error_handler("Connection String error. Please validate your configuration file.")
            return redirect(url_for('index'))
        else:
            with KustoClient(kusto_connection_string) as kusto_client:
                df = app.query_table(kusto_client, app.config.database_name, app.config.table_name, kql)
        
        print('RESULT_SET received in response from the OpenAI API:')

        print(df.to_markdown())

        # Convert the dataframe to an HTML table
        df_html_table = df.to_html(classes='table table-striped table-bordered')

        print("KQL run successfully, now generating insights...")

        insights_prompt_str = insights.insights_prompt.format(user_input=user_input, df_markdown=df.to_markdown())
        print('Insights Prompt to OpenAI API:')
        print(insights_prompt_str)
        print('Calling OpenAI API to generate insights...')
        insights_response = apis.call_openai(insights_prompt_str, user_input)
        print('Received insights in response from OpenAI API:')
        print(insights_response)
        print('Rendering insights in HTML...')
        markdown_output = markdown.markdown(insights_response)
        return render_template('response.html',
                               user_prompt = user_input,
                               kql_query = kql,
                               kql_response = df_html_table,
                               insights = markdown_output)
   else:
        print('Request received without any prompt from the user or blank prompt -- redirecting')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()
