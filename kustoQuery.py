import json
import pandas as pd
from dataclasses import dataclass

from azure.kusto.data import KustoClient
from azure.kusto.data.exceptions import KustoServiceError
from azure.kusto.data.helpers import dataframe_from_result_table
from apis import AuthenticationModeOptions, Utils

@dataclass
class ConfigJson:
    """
    ConfigJson object - represents a cluster and database connection configuration file.
    """
    database_name: str
    table_name: str
    kusto_uri: str
    authentication_mode: AuthenticationModeOptions
    wait_for_user: bool

    @staticmethod
    def from_json(json_dict: dict) -> "ConfigJson":
        config_json_keys = {
            "database_name": json_dict.get("databaseName"),
            "table_name": json_dict.get("tableName"),
            "kusto_uri": json_dict.get("kustoUri"),
            "authentication_mode": json_dict.get("authenticationMode"),
            "wait_for_user": json_dict.get("waitForUser", False)
        }
        return ConfigJson(**config_json_keys)

class KustoQueryApp:
    CONFIG_FILE_NAME = "kusto_sample_config.json"
    __step = 1
    config = None

    @classmethod
    def load_configs(cls, config_file_name: str) -> None:
        """
        Loads JSON configuration file.
        :param config_file_name: Configuration file path.
        """
        print('loading config file: {}'.format(config_file_name))
        try:
            with open(config_file_name, "r") as config_file:
                json_dict = json.load(config_file)
                cls.config = ConfigJson.from_json(json_dict)
        except Exception as ex:
            Utils.error_handler(f"Couldn't read config file '{config_file_name}'", ex)

    @classmethod
    def query_table(cls, kusto_client: KustoClient, database_name: str, table_name: str, command: str) -> pd.DataFrame:
        """
        Execute queries on the Kusto table.
        :param kusto_client: Client to run queries
        :param database_name: DB Name
        :param table_name: Table Name
        """
        df = pd.DataFrame()
        try:
            print(f"Executing command: {command}")
            response = kusto_client.execute_query(database_name, command)
            if response and response.primary_results:
                df = dataframe_from_result_table(response.primary_results[0])

        except KustoServiceError as ke:
            print(f"Kusto Service Error: {ke}")
            print(f"Failed command: {command}")
            raise ke
        except Exception as ex:
            print(f"Error: {ex}")
            print(f"Failed command: {command}")
            raise ex
        return df

    @classmethod
    def wait_for_user_to_proceed(cls, prompt_msg: str) -> None:
        """
        Handles UX on prompts and flow of program
        :param prompt_msg: Prompt to display to user
        """
        print()
        print(f"Step {cls.__step}: {prompt_msg}")
        cls.__step = cls.__step + 1
        if cls.config.wait_for_user:
            input("Press ENTER to proceed with this operation...")

# def main():
#     print("Kusto Query App is starting...")

#     app = KustoQueryApp()
#     app.load_configs(app.CONFIG_FILE_NAME)

#     if app.config.authentication_mode == "UserPrompt":
#         app.wait_for_user_to_proceed("You will be prompted for credentials during this script. Please return to the console after authenticating.")

#     kusto_connection_string = Utils.Authentication.generate_connection_string(app.config.kusto_uri, app.config.authentication_mode)
#     print(f"Using cluster URI: {app.config.kusto_uri}")

#     if not kusto_connection_string:
#         Utils.error_handler("Connection String error. Please validate your configuration file.")
#     else:
#         with KustoClient(kusto_connection_string) as kusto_client:
#             app.query_table(kusto_client, app.config.database_name, app.config.table_name)

#     print("\nKusto Query App done")

# if __name__ == "__main__":
#     main()
