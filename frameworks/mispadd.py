from pymisp import ExpandedPyMISP, MISPEvent, MISPObject
from io import BytesIO
class Main:
    def __init__(self):
        self.key_misp = 'CHAVE-DO-MISP'
        self.url_misp = "URL-DO-MISP"
        self.misp = ExpandedPyMISP(self.url_misp, self.key_misp, False)
        
    def start(self,enterprise:str,photo:str,date_post:str,url:str,description:str) -> None:
        with open(photo,'rb') as f:
            data = BytesIO(f.read())
        
        self.misp_object = None
        self.misp_object = MISPObject(name="leaked-document")
        self.misp_object.add_attribute('origin',f"Threat Actor: {description}")
        self.misp_object.add_attribute('document-name', f'{enterprise}')
        self.misp_object.add_attribute('url', f'{url}')
        self.misp_object.add_attribute("attachment", value=f'{photo}',data=data, expand='binary')
        self.misp_object.add_attribute('first-seen', f'{date_post}')
        self.misp.add_object('EVENT-ID', self.misp_object)