# views.py

from django.shortcuts import render, redirect
from django.conf import settings
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from django.http import HttpResponseBadRequest

def google_drive_auth(request):
    # Define the scopes for Google Drive API
    SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly']

    # Define the OAuth2 flow
    flow = Flow.from_client_config(
        settings.GOOGLE_OAUTH2_CLIENT_SECRETS_JSON,
        scopes=SCOPES,
        redirect_uri=settings.GOOGLE_OAUTH2_REDIRECT_URI,
    )

    # Generate the authorization URL
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
    )
    print(authorization_url,"______________>>>>>>",state)

    # Save the state to the session
    request.session['oauth2_state'] = state

    # Redirect the user to Google's OAuth2 consent screen
    return redirect(authorization_url)

def google_drive_callback(request):
    # Check if the states match (prevents CSRF attacks)
    if request.session.get('oauth2_state') != request.GET.get('state'):
        return HttpResponseBadRequest('Invalid state parameter')

    # Get the authorization code from the callback URL
    authorization_code = request.GET.get('code')
    print("??????",authorization_code,request.GET.get('state'))

    # Exchange the authorization code for OAuth2 credentials
    flow = Flow.from_client_config(
        settings.GOOGLE_OAUTH2_CLIENT_SECRETS_JSON,
        scopes=['https://www.googleapis.com/auth/drive.metadata.readonly'],
        redirect_uri=settings.GOOGLE_OAUTH2_REDIRECT_URI,
    )
    print("po"  ,request.build_absolute_uri())
    flow.fetch_token(authorization_response=request.build_absolute_uri())
    credentials = flow.credentials
    print("oooo")
    # Create a Google Drive API service using the credentials
    service = build('drive', 'v3', credentials=credentials)

    # List all files and documents from the user's Google Drive
    results = service.files().list(
        pageSize=10,
        fields="nextPageToken, files(id, name)"
    ).execute()
    items = results.get('files', [])
    print("items are",items)

    # Render a template with the list of files and documents
    return render(request, 'google_drive_files.html', {'files': items})
