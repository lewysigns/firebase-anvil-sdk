import anvil.js
from .helper import utility

proxy_fs = anvil.js.import_from("https://www.gstatic.com/firebasejs/9.9.4/firebase-firestore.js")
db = None #initialized with init() -> late


def init(app,enable_offline_cache):
  '''initalizes the firestore module'''
  global db
  db = proxy_fs.getFirestore(app)

  #TODO configure cache size

  #Offline Caching
  if enable_offline_cache:
    try:
      anvil.js.await_promise(proxy_fs.enableIndexedDbPersistence(db))
    except Exception as e:
      print('Error enabeling offline persistance',e)
    
def disable_network():
  '''forces all subsequent queries to the offline cache'''
  anvil.js.await_promise(proxy_fs.disableNetwork(db))

def enable_network():
  '''reverts disable_network'''
  anvil.js.await_promise(proxy_fs.disableNetwork(db))
  
  

'''Helper Methods'''
def collection(db,collection_name):
  return proxy_fs.collection(db,collection_name)

def doc(db,collection_name,doc_uid):
  return proxy_fs.doc(db, collection_name, doc_uid)

def where(key,operator,value):
  return proxy_fs.where(key,operator,value)

def orderBy(attribute,sort_by):
  return proxy_fs.orderBy(attribute,sort_by)

def limit(amount=100):
  return proxy_fs.limit(amount)

def query(collection,where):
  if not isinstance(where,list): where = [where]
  return proxy_fs.query(collection,*where)
  

'''Data Manipulation'''
def add_doc(collection,doc_data):
  return proxy_fs.addDoc(collection,utility.to_proxy(doc_data))

def set_doc(doc_ref,doc_data,merge=False):
  '''Set a document'''
  return proxy_fs.setDoc(doc_ref,utility.to_proxy(doc_data),{'merge':merge})

def update_doc(doc_ref,update_dict):
  return proxy_fs.updateDoc(doc_ref,utility.to_proxy(update_dict))

def get_doc(doc_ref)->tuple:
  '''Returns uid,data or None,Error '''
  doc_snap = proxy_fs.getDoc(doc_ref)
  if doc_snap.exists():
    return doc_snap.id,utility.from_proxy(doc_snap.data())
  else:
    return None,'Document does not exist'

def delete_doc(doc_ref):
  return proxy_fs.deleteDoc(doc_ref)
  

def get_docs(query)->list:
  '''ececutes a query and returns a list of uid,data tuples '''
  querySnapshot = proxy_fs.getDocs(query);
  ret_list = []
  def get_docs(doc):
    ret_list.append((doc.id,utility.from_proxy(doc.data())))
    
  querySnapshot.forEach(get_docs)
  return ret_list

def listen_to_docs(query,callback):
  from .helper.listener import Listener
  #import { collection, query, where, onSnapshot } from "firebase/firestore";
  l = Listener(callback)
  l.unsubscribe = proxy_fs.onSnapshot(query,l._proxy_callback)
  return l

def write_batch():
  from .helper.batch import Batch
  return Batch(proxy_fs.writeBatch(db))

def run_transaction(function):
  '''Takes in a function which must be run as a transaction'''
  return anvil.js.await_promise(proxy_fs.runTransaction(db,function))


  





