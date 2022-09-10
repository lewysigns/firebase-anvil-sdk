from ._anvil_designer import test_formTemplate
from anvil import *
from ...firebase_client import firestore as fs

class test_form(test_formTemplate):
  def __init__(self, **properties):
    # Set Form properties and Data Bindings.
    self.init_components(**properties)

  def add_doc_btn_click(self, **event_args):
    collection = fs.collection(fs.db,'test_collection')
    fs.add_doc(collection,{'key':'some_value'})

  def set_doc_btn_click(self, **event_args):
    doc_ref = fs.doc(fs.db,'test_collection','some_uid')
    fs.set_doc(doc_ref,{'key':'some_value'})

  def update_doc_click(self, **event_args):
    doc_ref = fs.doc(fs.db,'test_collection','some_uid')
    fs.update_doc(doc_ref,{'key':'new_value'})
    
  def get_doc_btn_click(self, **event_args):
    doc_ref = fs.doc(fs.db,'test_collection','some_uid')
    doc_uid,doc_data = fs.get_doc(doc_ref)
    print(doc_uid,doc_data)

  def get_query_btn_click(self, **event_args):
    test_collection = fs.collection(fs.db,'test_collection')
    q = fs.query(test_collection,[fs.where('key','==','some_value'),fs.where('key','==','some_value')])
    documents = fs.get_docs(q)
    print(documents)

  def set_listener_btn_click(self, **event_args):
    test_collection = fs.collection(fs.db,'test_collection')
    q = fs.query(test_collection,fs.where('key','==','some_value'))
    listener = fs.listen_to_docs(q,self.listener_changed)

  def listener_changed(self,data):
    print(data)
    Notification('new data arrived',timeout=5).show()








    

  



