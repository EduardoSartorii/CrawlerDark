#! -*- coding: utf-8 -*-

__author__ = 'Eduardo Henrique '
__license__ = "MIT"
__version__ = "2.0.1"

import logging
import time
import datetime
import os
import json
from selenium import webdriver
from bs4 import BeautifulSoup as bs
from frameworks.mispadd import Main as feedmisp
from frameworks.database import Database
from datetime import datetime, date
from PIL import Image
import pytesseract

class VigilantOnion:
    def __init__(self,save_path_log:str, debug:bool, webdriver_path:str):
        if debug:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S',

            )
        else:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S',
            )

        self.logger = logging.getLogger(__name__)
        self.headless = True
        self.options = webdriver.FirefoxOptions()
        if self.headless:
            self.options.add_argument("-headless")
            self.logger.info("Headless está ativado, o browser não será aberto.")
        else:
            self.logger.info("Headless está desativado, o browser será aberto.")         
        self.profile = webdriver.FirefoxProfile()
        self.profile.set_preference('network.proxy.type', 1)
        self.profile.set_preference('network.proxy.socks', "127.0.0.1")
        self.profile.set_preference('network.proxy.socks_port', 9050)
        self.profile.set_preference('network.proxy.socks_version', 5)
        self.profile.set_preference('network.proxy.socks_remote_dns', True)
        self.profile.update_preferences()
        self.webdriver_path = webdriver_path
        self.database = Database(database_name='oniondb', database_path='utils/database/')
        self.onion_urls = "http://darksidedxcftmqa.onion/"
        self.save_path_log = save_path_log
        self.feedmisp = feedmisp()
    @property
    def start(self):
        try:
            self.driver= webdriver.Firefox(options=self.options,firefox_profile=self.profile, executable_path=self.webdriver_path)
            self.logger.info("[STATUS] Iniciando coleta nas urls onion")
            self.parser_list_urls()
        except Exception as error:
            self.logger.info(f'[ERROR] Não foi possível realizar o vigilant onion, Motivo: {error}')

    def parser_list_urls(self):
        try:
            self.connect_onion_url(url=self.onion_urls)
        except Exception as error:
            self.logger.info(f"[ERROR] Não foi possível realizar o parser na lista; Motivo: {error}")
    
    def connect_onion_url(self, url:str) -> None:
        try:
            self.driver.get(f"{url}")
            self.parser_html(content= bs(self.driver.page_source, "html.parser"), url=url)
        except Exception as error:
            self.logger.info(f"[ERROR] Não foi possível conectar na Url; Motivo: {error}")

    def parser_html(self, content:str,url:str) -> None:
        try:
            time.sleep(15)
            feed = content.find('div', {"id" : "content"})
            for post in feed.find_all('div', {"class" : "card"}):
                title = post.find("h5").getText()
                _name_enterprise = title.split("-")[0]
                url_post = post.find("a")
                _url_post = url_post.get("href")
                self.driver.get(f"http://darksidedxcftmqa.onion{_url_post}")
                self.parser_event(name_enterprise=_name_enterprise,content= bs(self.driver.page_source, "html.parser"))
        except Exception as error:
            self.logger.info(f"[ERROR] Não foi possível coletar as páginas de evento; Motivo{error}")
    def validateDB(self, data:str, enterprise:str) -> bool:
        if self.database.compare(data=data,enterprise=enterprise):
            self.logger.debug(f"[ALERT] A url: {data} ja está no banco de dados")
            return False
        else:
            self.logger.info("[ALERT] Estamos salvando a url no banco de dados")
            if self.database.save(data=data, enterprise=enterprise):
                return True
            else:
                self.logger.info(f"[ERROR] Não foi possível salvar a informação no banco de dados, motivo: {self.database.save(data=data,enterprise=enterprise)}")
                return False    
    def parser_event(self,name_enterprise:str,content:str) -> None:
        try:
            time.sleep(5)
            name_file = f"utils/screenshot/{datetime.today().strftime('%Y-%m-%d-%H-%M-%S-%f')}-darkside.png"
            if self.validateDB(data=name_enterprise,enterprise="onion") is not False:
                self.driver.get_screenshot_as_file(name_file)
                self.feedmisp.start(date_post= datetime.today().strftime("%Y-%m-%d"),enterprise= name_enterprise, url="N/A", description= "Darkside",photo=name_file)
            else:
                self.logger.info("[STATUS] Está informação já foi adicionada no MISP...")                

        except Exception as error:
            self.logger.info(f"[ERROR] Não foi possível realizar o parse no evento; Motivo: {error}")
