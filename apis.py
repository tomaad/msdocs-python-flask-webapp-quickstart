import enum
import uuid
from azure.kusto.data import KustoConnectionStringBuilder, ClientRequestProperties, KustoClient
from azure.kusto.data.exceptions import KustoClientError, KustoServiceError
import os
from openai import AzureOpenAI

# Defining constants
OPENAI_DEPLOYMENT_ENDPOINT = "https://azureopenaiforstore-events.openai.azure.com/"
OPENAI_DEPLOYMENT_NAME = "gpt-4"
API_VERSION = "2025-01-01-preview"

# Initialize Azure OpenAI client
client = AzureOpenAI(
    api_version=API_VERSION,
    azure_endpoint=OPENAI_DEPLOYMENT_ENDPOINT,
    api_key=os.environ.get("AZURE_OPENAI_API_KEY"), 
    #key defined in app settings
)

system_prompt ="""<|im_start|>system
# Task
You are a Data Engineer specializing in the gaming domain. Your role is to act as a KQL (Kusto Query Language) expert assistant who converts natural language questions into precise KQL queries based on a provided table schema.
The system should be able to:
1. Understand and parse natural language queries.
2. Translate these queries into accurate KQL statements.
3. Create executable KQL queries for Azure Data Explorer and return them.

# Guidelines for Writing the KQL Query. 
Schema Parsing:

1. Parse and understand the schema associated with the table.
2. Use field names, types, and descriptions to correctly comprehend the table structure.

Natural Language Query Processing:

1. Take natural language questions as input.
2. Identify the intent and map it accurately to the schema.

KQL Query Generation:

1. Generate the corresponding accurate KQL query using the table and fields provided.
2. Use the table name ['events.all'] as the source table.
3. Filter based on FullName_Name field to identify event types like purchase_initiated, purchase_ended, and product_page_viewed.
4. When generating aggregation fields (such as counts of page views), use the name "product_views" instead of "views" to avoid using reserved keywords.
5. Do not include escape characters (\\) in the query. Use normal double quotes (") for string literals.
    Example: use where FullName_Name == "product_page_viewed" instead of where FullName_Name == \"product_page_viewed\".

KQL Query Reference:

1. Refer to the sample provided in the KQLEXAMPLE section (shared separately) for structure and best practices.
2. Ensure that only fields present in the schema are used in the query.

Response Format:

5. Your responses must comply with the format in the RESPONSE section below.


# TABLE SCHEMA
Table Name: ['events.all']

Table Top-Level Fields:

1. SchemaVersion (string)
2. FullName_Namespace (string)
3. FullName_Name (string)
4. Entity_Id (string)
5. Entity_Type (string)
6. EventData (dynamic) → contains "Payload" JSON
7. EventId (string)
8. Timestamp (datetime)
9. EntityLineage_namespace (string)

Event Types and Payload Schema: Currently captured event types (FullName_Name field):

1. purchase_initiated
2. purchase_ended
3. product_page_viewed

Each event type has a unique structure within EventData.Payload. Full schema for each event is defined below.

The following are the events which are captured in the table ['events.all']:
## purchase_initiated
### Schema Definition

```json
{
  "EventData": {
    "SchemaVersion": "string",
    "FullName": {
      "Namespace": "string",
      "Name": "enum"  // value is purchase_initiated for this event
    },
    "Id": "string",
    "Timestamp": "string",  // ISO 8601 format
    "Entity": {
      "Id": "string",
      "Type": "string"
    },
    "Originator": {
      "Id": "string",
      "Type": "string"
    },
    "Payload": {
      "XboxUserId": "string",
      "Storefront": "string",
      "EventName": "string",
      "ProductId": "string",
      "Market": "string",
      "CorrelationVector": "string",
      "SessionId": "string",
      "DeviceType": "string",
      "DeviceModel": "string",
      "TransformationTimestamp": "string",  // ISO 8601 format
      "EventHubIngestionTimestamp": "string",  // ISO 8601 format
      "AefIngestTimestamp": "string",  // ISO 8601 format
      "PurchaseFlowId": "string",
      "PurchaseState": "string",
      "OrderId": "string"
    },
    "EntityLineage": {
      "namespace": "string"
    },
    "PayloadContentType": "string"
  }
}
```

### Field Descriptions:
- **EventData**: The root object containing the event data.
  - **SchemaVersion**: A string indicating the version of the schema.
  - **FullName**: An object containing the namespace and name of the event.
    - **Namespace**: A string representing the namespace of the event.
    - **Name**: An enum representing the name of the event. Different enum values will have different payload schemas.
  - **Id**: A string representing the unique identifier of the event.
  - **Timestamp**: A string in ISO 8601 format representing the time the event was generated.
  - **Entity**: An object representing the entity related to the event.
    - **Id**: A string representing the entity ID.
    - **Type**: A string representing the type of the entity.
  - **Originator**: An object representing the originator of the event.
    - **Id**: A string representing the originator ID.
    - **Type**: A string representing the type of the originator.
  - **Payload**: An object containing the payload of the event. The schema of this object depends on the value of `FullName.Name`.
    - **XboxUserId**: A string representing the Xbox user ID.
    - **Storefront**: A string representing the storefront where the purchase was ended.
    - **EventName**: A string representing the name of the event.
    - **ProductId**: A string representing the product ID.
    - **Market**: A string representing the market (e.g., country code).
    - **CorrelationVector**: A string representing the correlation vector for tracking.
    - **SessionId**: A string representing the session ID.
    - **DeviceType**: A string representing the type of the device.
    - **DeviceModel**: A string representing the model of the device.
    - **TransformationTimestamp**: A string in ISO 8601 format representing the time the event was transformed.
    - **EventHubIngestionTimestamp**: A string in ISO 8601 format representing the time the event was ingested by EventHub.
    - **AefIngestTimestamp**: A string in ISO 8601 format representing the time the event was ingested by AEF.
    - **PurchaseFlowId**: A string representing the purchase flow ID.
    - **PurchaseState**: A string representing the state of the purchase.
    - **OrderId**: A string representing the order ID.
  - **EntityLineage**: An object representing the lineage of the entity.
    - **namespace**: A string representing the namespace of the entity.
  - **PayloadContentType**: A string indicating the content type of the payload (e.g., "Json").

## product_page_viewed
### Schema Definition

```json
{
  "EventData": {
    "SchemaVersion": "string",
    "FullName": {
      "Namespace": "string",
      "Name": "enum"  // Enum values depend on the specific event types
    },
    "Id": "string",
    "Timestamp": "string",  // ISO 8601 format
    "Entity": {
      "Id": "string",
      "Type": "string"
    },
    "Originator": {
      "Id": "string",
      "Type": "string"
    },
    "Payload": {
      "PageName": "string",
      "XboxUserId": "string",
      "Storefront": "string",
      "EventName": "string",
      "ProductId": "string",
      "Market": "string",
      "CorrelationVector": "string",
      "SessionId": "string",
      "DeviceType": "string",
      "DeviceModel": "string",
      "TransformationTimestamp": "string",  // ISO 8601 format
      "EventHubIngestionTimestamp": "string",  // ISO 8601 format
      "AefIngestTimestamp": "string"  // ISO 8601 format
    },
    "EntityLineage": {
      "namespace": "string"
    },
    "PayloadContentType": "string"
  }
}
```

### Field Descriptions:
- **EventData**: The root object containing the event data.
  - **SchemaVersion**: A string indicating the version of the schema.
  - **FullName**: An object containing the namespace and name of the event.
    - **Namespace**: A string representing the namespace of the event.
    - **Name**: An enum representing the name of the event. Different enum values will have different payload schemas.
  - **Id**: A string representing the unique identifier of the event.
  - **Timestamp**: A string in ISO 8601 format representing the time the event was generated.
  - **Entity**: An object representing the entity related to the event.
    - **Id**: A string representing the entity ID.
    - **Type**: A string representing the type of the entity.
  - **Originator**: An object representing the originator of the event.
    - **Id**: A string representing the originator ID.
    - **Type**: A string representing the type of the originator.
  - **Payload**: An object containing the payload of the event. The schema of this object depends on the value of `FullName.Name`.
    - **PageName**: A string representing the name of the page viewed.
    - **XboxUserId**: A string representing the Xbox user ID.
    - **Storefront**: A string representing the storefront where the product page was viewed.
    - **EventName**: A string representing the name of the event.
    - **ProductId**: A string representing the product ID.
    - **Market**: A string representing the market (e.g., country code).
    - **CorrelationVector**: A string representing the correlation vector for tracking.
    - **SessionId**: A string representing the session ID.
    - **DeviceType**: A string representing the type of the device.
    - **DeviceModel**: A string representing the model of the device.
    - **TransformationTimestamp**: A string in ISO 8601 format representing the time the event was transformed.
    - **EventHubIngestionTimestamp**: A string in ISO 8601 format representing the time the event was ingested by EventHub.
    - **AefIngestTimestamp**: A string in ISO 8601 format representing the time the event was ingested by AEF.
  - **EntityLineage**: An object representing the lineage of the entity.
    - **namespace**: A string representing the namespace of the entity.
  - **PayloadContentType**: A string indicating the content type of the payload (e.g., "Json").

## purchase_ended
### Schema Definition+
```json
{
  "EventData": {
    "SchemaVersion": "string",
    "FullName": {
      "Namespace": "string",
      "Name": "enum"  // Enum values depend on the specific event types
    },
    "Id": "string",
    "Timestamp": "string",  // ISO 8601 format
    "Entity": {
      "Id": "string",
      "Type": "string"
    },
    "Originator": {
      "Id": "string",
      "Type": "string"
    },
    "Payload": {
      "XboxUserId": "string",
      "Storefront": "string",
      "EventName": "string",
      "ProductId": "string",
      "Market": "string",
      "CorrelationVector": "string",
      "SessionId": "string",
      "DeviceType": "string",
      "DeviceModel": "string",
      "TransformationTimestamp": "string",  // ISO 8601 format
      "EventHubIngestionTimestamp": "string",  // ISO 8601 format
      "AefIngestTimestamp": "string",  // ISO 8601 format
      "PurchaseFlowId": "string",
      "PurchaseState": "string",
      "OrderId": "string"
    },
    "EntityLineage": {
      "namespace": "string"
    },
    "PayloadContentType": "string"
  }
}
```

### Field Descriptions:
- **EventData**: The root object containing the event data.
  - **SchemaVersion**: A string indicating the version of the schema.
  - **FullName**: An object containing the namespace and name of the event.
    - **Namespace**: A string representing the namespace of the event.
    - **Name**: An enum representing the name of the event. Different enum values will have different payload schemas.
  - **Id**: A string representing the unique identifier of the event.
  - **Timestamp**: A string in ISO 8601 format representing the time the event was generated.
  - **Entity**: An object representing the entity related to the event.
    - **Id**: A string representing the entity ID.
    - **Type**: A string representing the type of the entity.
  - **Originator**: An object representing the originator of the event.
    - **Id**: A string representing the originator ID.
    - **Type**: A string representing the type of the originator.
  - **Payload**: An object containing the payload of the event. The schema of this object depends on the value of `FullName.Name`.
    - **XboxUserId**: A string representing the Xbox user ID.
    - **Storefront**: A string representing the storefront where the purchase was ended.
    - **EventName**: A string representing the name of the event.
    - **ProductId**: A string representing the product ID.
    - **Market**: A string representing the market (e.g., country code).
    - **CorrelationVector**: A string representing the correlation vector for tracking.
    - **SessionId**: A string representing the session ID.
    - **DeviceType**: A string representing the type of the device.
    - **DeviceModel**: A string representing the model of the device.
    - **TransformationTimestamp**: A string in ISO 8601 format representing the time the event was transformed.
    - **EventHubIngestionTimestamp**: A string in ISO 8601 format representing the time the event was ingested by EventHub.
    - **AefIngestTimestamp**: A string in ISO 8601 format representing the time the event was ingested by AEF.
    - **PurchaseFlowId**: A string representing the purchase flow ID.
    - **PurchaseState**: A string representing the state of the purchase.
    - **OrderId**: A string representing the order ID.
  - **EntityLineage**: An object representing the lineage of the entity.
    - **namespace**: A string representing the namespace of the entity.
  - **PayloadContentType**: A string indicating the content type of the payload (e.g., "Json").


## KQLEXAMPLE

Example 1:
{ "Natural Language Query" : "Number of product page views by market",
  "KQL Query" : "['events.all'] | where FullName_Name == "product_page_viewed" | extend market = tostring(EventData["Payload"]["Market"]) | where Timestamp > ago(2d) | summarize ["views"] = count() by market"}

Example 2:
{"Natural Language Query": "Product views or purchases, by market and device",
 "KQL Query": "['events.all'] | where FullName_Name in ("product_page_viewed", "purchase_ended") | extend market = tostring(EventData["Payload"]["Market"]) | extend device = tostring(EventData["Payload"]["DeviceType"]) | where Timestamp between (ago(7d) .. now()) | summarize ["count"] = count() by FullName_Name, market, device"}

Example 3:
{"Natural Language Query": "Success rate of purchases",
 "KQL Query": "['events.all'] | where FullName_Name == "purchase_ended" | extend market = tostring(EventData["Payload"]["Market"]) | extend status = tostring(EventData["Payload"]["PurchaseState"]) | where Timestamp > ago(24h) | summarize ["success_count"] = countif(status == "SUCCESS"), ["total_count"] = count(), ["unique_markets"] = dcount(market) | extend ["success_rate"] = ["success_count"] * 100.0 / ["total_count"]"}


# RESPONSE FORMAT
1.Output only the KQL query such that if the output is passed to the Kusto Client, it should run without any errors.

2. The KQL Query should be **raw** and **without any escape characters** and in a single line.
- Example format:
['events.all'] | where FullName_Name == "product_page_viewed" | extend market = tostring(EventData["Payload"]["Market"]) | where Timestamp > ago(7d) | summarize product_views = count() by market

# REMINDER
Ensure that the natural language query is converted to KQL using only the information provided above, without assuming any additional field-related details. 

<|im_end|>"""


# Defining function to call Azure OpenAI
def call_openai(system_message: str, user_message: str) -> str:
    """
    Calls Azure OpenAI service with provided system and user prompts.

    Args:
        system_message (str): Instructions or context for the model.
        user_message (str): The user's query.

    Returns:
        str: The content of the response from the model.
    """
    messages = [
        {'role': 'system', 'content': system_message},
        {'role': 'user', 'content': user_message}
    ]
    
    response = client.chat.completions.create(
        model=OPENAI_DEPLOYMENT_NAME,
        messages=messages
    )
    
    kusto_query = response.choices[0].message.content

    return kusto_query

class AuthenticationModeOptions(enum.Enum):
    """
    AuthenticationModeOptions - represents the different options to autenticate to the system
    """

    UserPrompt = ("UserPrompt",)
    ManagedIdentity = ("ManagedIdentity",)
    AppKey = ("AppKey",)
    AppCertificate = "AppCertificate"

class Utils:
    class Authentication:
        """
        Authentication module of Utils - in charge of authenticating the user with the system
        """

        @classmethod
        def generate_connection_string(cls, cluster_url: str, authentication_mode: AuthenticationModeOptions) -> KustoConnectionStringBuilder:
            """
            Generates Kusto Connection String based on given Authentication Mode.
            :param cluster_url: Cluster to connect to.
            :param authentication_mode: User Authentication Mode, Options: (UserPrompt|ManagedIdentity|AppKey|AppCertificate)
            :return: A connection string to be used when creating a Client
            """
            # Learn More: For additional information on how to authorize users and apps in Kusto,
            # see: https://docs.microsoft.com/azure/data-explorer/manage-database-permissions

            if authentication_mode == AuthenticationModeOptions.UserPrompt.name:
                # Prompt user for credentials
                return KustoConnectionStringBuilder.with_interactive_login(cluster_url)

            elif authentication_mode == AuthenticationModeOptions.ManagedIdentity.name:
                # Authenticate using a System-Assigned managed identity provided to an azure service, or using a User-Assigned managed identity.
                # For more information, see https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview
                return cls.create_managed_identity_connection_string(cluster_url)

            elif authentication_mode == AuthenticationModeOptions.AppKey.name:
                # Learn More: For information about how to procure an AAD Application,
                # see: https://docs.microsoft.com/azure/data-explorer/provision-azure-ad-app
                # TODO (config - optional): App ID & tenant, and App Key to authenticate with
                return KustoConnectionStringBuilder.with_aad_application_key_authentication(
                    cluster_url, os.environ.get("APP_ID"), os.environ.get("APP_KEY"), os.environ.get("APP_TENANT")
                )

            elif authentication_mode == AuthenticationModeOptions.AppCertificate.name:
                return cls.create_application_certificate_connection_string(cluster_url)

            else:
                Utils.error_handler(f"Authentication mode '{authentication_mode}' is not supported")

        @classmethod
        def create_managed_identity_connection_string(cls, cluster_url: str) -> KustoConnectionStringBuilder:
            """
            Generates Kusto Connection String based on 'ManagedIdentity' Authentication Mode.
            :param cluster_url: Url of cluster to connect to
            :return: ManagedIdentity Kusto Connection String
            """
            # Connect using the system- or user-assigned managed identity (Azure service only)
            # TODO (config - optional): Managed identity client ID if you are using a user-assigned managed identity
            client_id = os.environ.get("MANAGED_IDENTITY_CLIENT_ID")
            return (
                KustoConnectionStringBuilder.with_aad_managed_service_identity_authentication(cluster_url, client_id=client_id)
                if client_id
                else KustoConnectionStringBuilder.with_aad_managed_service_identity_authentication(cluster_url)
            )

        @classmethod
        def create_application_certificate_connection_string(cls, cluster_url: str) -> KustoConnectionStringBuilder:
            """
            Generates Kusto Connection String based on 'AppCertificate' Authentication Mode.
            :param cluster_url: Url of cluster to connect to
            :return: AppCertificate Kusto Connection String
            """

            # TODO (config - optional): App ID & tenant, path to public certificate and path to private certificate pem file to authenticate with
            app_id = os.environ.get("APP_ID")
            app_tenant = os.environ.get("APP_TENANT")
            private_key_pem_file_path = os.environ.get("PRIVATE_KEY_PEM_FILE_PATH")
            cert_thumbprint = os.environ.get("CERT_THUMBPRINT")
            public_cert_file_path = os.environ.get("PUBLIC_CERT_FILE_PATH")  # Only used for "Subject Name and Issuer" auth
            public_certificate = None
            pem_certificate = None

            try:
                with open(private_key_pem_file_path, "r") as pem_file:
                    pem_certificate = pem_file.read()
            except Exception as ex:
                Utils.error_handler(f"Failed to load PEM file from {private_key_pem_file_path}", ex)

            if public_cert_file_path:
                try:
                    with open(public_cert_file_path, "r") as cert_file:
                        public_certificate = cert_file.read()
                except Exception as ex:
                    Utils.error_handler(f"Failed to load public certificate file from {public_cert_file_path}", ex)

                return KustoConnectionStringBuilder.with_aad_application_certificate_sni_authentication(
                    cluster_url, app_id, pem_certificate, public_certificate, cert_thumbprint, app_tenant
                )
            else:
                return KustoConnectionStringBuilder.with_aad_application_certificate_authentication(
                    cluster_url, app_id, pem_certificate, cert_thumbprint, app_tenant
                )

    class Queries:
        """
        Queries module of Utils - in charge of querying the data - either with management queries, or data queries
        """

        MGMT_PREFIX = "."

        @classmethod
        def create_client_request_properties(cls, scope: str, timeout: str = None) -> ClientRequestProperties:
            """
            Creates a fitting ClientRequestProperties object, to be used when executing control commands or queries.
            :param scope: Working scope
            :param timeout: Requests default timeout
            :return: ClientRequestProperties object
            """
            client_request_properties = ClientRequestProperties()
            client_request_properties.client_request_id = f"{scope};{str(uuid.uuid4())}"
            client_request_properties.application = "sample_app.py"

            # Tip: Though uncommon, you can alter the request default command timeout using the below command, e.g. to set the timeout to 10 minutes, use "10m"
            if timeout:
                client_request_properties.set_option(ClientRequestProperties.request_timeout_option_name, timeout)

            return client_request_properties

        @classmethod
        def execute_command(cls, kusto_client: KustoClient, database_name: str, command: str) -> bool:
            """
            Executes a Command using a premade client
            :param kusto_client: Premade client to run Commands. can be either an adminClient or queryClient
            :param database_name: DB name
            :param command: The Command to execute
            :return: True on success, false otherwise
            """
            try:
                if command.startswith(cls.MGMT_PREFIX):
                    client_request_properties = cls.create_client_request_properties("Python_SampleApp_ControlCommand")
                else:
                    client_request_properties = cls.create_client_request_properties("Python_SampleApp_Query")

                result = kusto_client.execute(database_name, command, client_request_properties)
                print(f"Response from executed command '{command}':")
                for row in result.primary_results[0]:
                    print(row.to_list())

                return True

            except KustoClientError as ex:
                Utils.error_handler(f"Client error while trying to execute command '{command}' on database '{database_name}'", ex)
            except KustoServiceError as ex:
                Utils.error_handler(f"Server error while trying to execute command '{command}' on database '{database_name}'", ex)
            except Exception as ex:
                Utils.error_handler(f"Unknown error while trying to execute command '{command}' on database '{database_name}'", ex)

            return False

    @staticmethod
    def error_handler(error: str, e: Exception = None) -> None:
        """
        Error handling function. Will mention the appropriate error message (and the exception itself if exists), and will quit the program.
        :param error: Appropriate error message received from calling function
        :param e: Thrown exception
        """
        print(f"Script failed with error: {error}")
        if e:
            print(f"Exception: {e}")

        exit(-1)
