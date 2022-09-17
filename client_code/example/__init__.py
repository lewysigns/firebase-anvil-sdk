
def run():
  '''Run Firestore serverless example'''

  #1. initialize firebase app
  from ..firebase_client import initialize_app
  initialize_app({
      'apiKey': "AIzaSyDusPnQZzPbV8I_nnwKW1Oj5PbSj_0BLDs",
      'authDomain': "development-945bf.firebaseapp.com",
      'projectId': "development-945bf",
      'storageBucket': "development-945bf.appspot.com",
      'messagingSenderId': "273735084857",
      'appId': "1:273735084857:web:4afc77ceec6c33fde556e8",
      'measurementId': "G-ZTBXYR2MK4"
  })

  #2. authenticate
  
  
  #3. show test ui
  import anvil
  anvil.open_form('example.test_form')

  
