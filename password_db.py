#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
    Password Store PyQt4

    Usefull to read:
        * AES: 
            http://codeghar.wordpress.com/2011/09/01/aes-encryption-with-python/
        * PyQt4: 
            http://zetcode.com/
        * PyQt Class Reference: 
            http://www.riverbankcomputing.co.uk/static/Docs/PyQt4/html/classes.html
        * SQLite:
            http://www.sqlite.org/

"""

import sys
import hashlib
import sqlite3
import os.path
from Crypto.Cipher import AES
from PyQt4 import QtGui
from PyQt4 import QtCore
from base64 import b64encode
from base64 import b64decode

class frickelAES_CBC(object):
    def __init__(self, password, initialvector):
        self.__blockSize = 32
        self.__interrupt = u'\u0001'
        self.__pad = u'\u0000'

        self.__initCrypto(password, initialvector)

    def __initCrypto(self, password, initialVector):
        self.__cipher = AES.new(password, AES.MODE_CBC, initialVector)

    def __addPadding(self, data):
        newData = ''.join( map( str, [data, self.__interrupt] ))
        padString = self.__pad * (self.__blockSize - (len(newData) % self.__blockSize))
        return ''.join([newData, padString])

    def __stripPadding(self, data):
        return data.decode('utf8',  'ignore').rstrip(self.__pad).rstrip(self.__interrupt)

    def encryptData(self, plaintextData):
        plaintextPadded = self.__addPadding(plaintextData)
        #encryptedData = self.__cipher.encrypt(plaintextPadded)
        #return encryptedData
        return self.__cipher.encrypt(plaintextPadded)


    def decryptData(self, encryptedData):
        decryptedData = self.__cipher.decrypt(encryptedData)
        return self.__stripPadding(decryptedData)

class frickelSQLite(object):
    def __init__(self, filename):
        self.__sqlite = sqlite3.connect(filename)

    def selectData(self):
        """
        ToDo:
            * selectData need SQL select per input
        """
        sqliteSelect = '''
                 SELECT      
                    Benutzer  
                    , Passwort  
                    , Bemerkung 
                FROM         
                    password
                ORDER BY 
                    ID
                '''
        try:
            conn = self.__sqlite.cursor()
            rows = conn.execute(sqliteSelect)
        except:
            """
            ToDo:
                * better error handling
                    * sqlite3.OperationalError
            """
            error = False
            
        else:
            error = rows.fetchall()
        finally:
            if conn:
                conn.close()
            return error
   
    def insertData(self,  data):        
        try: 
            conn = self.__sqlite.cursor()
            conn.execute("INSERT INTO password VALUES (NULL,?,?,?)", data)
            self.__sqlite.commit()
        except:
            """
            ToDo:
                * better error handling
                    * sqlite3.Error
            """
            error = False
        else:
            error = True
        finally:
            if conn:
                conn.close()
            return error

    def deleteData(self, rowid):
        try:
            conn = self.__sqlite.cursor()
            conn.execute("DELETE FROM password WHERE id=?", (rowid,))
            self.__sqlite.commit()
        except:
            error = False
        else:
            error = True
        finally:
            if conn:
                conn.close()
            return error
        
    def createTable(self):
        try:
            conn = self.__sqlite.cursor()
            conn.execute('''CREATE TABLE password
                    (id INTEGER PRIMARY KEY, Benutzer TEXT, Passwort TEXT, Bemerkung TEXT)''')
            self.__sqlite.commit()
        except:
            """
            ToDo:
                * better error handling
            """
            error = False
        else:
            error = True
        finally:
            if conn:
                conn.close()
            return error

class frickelConfig(object):
    def __init__(self):
	pass

    def save(self):
	pass

    def load(self):
	pass

class PasspharseDialog(QtGui.QWidget):
    def __init__(self):
        super(PasspharseDialog, self).__init__()
        self.initUI()
        
    def initUI(self):      
        salt = "fr88dlNZkJwE"
        text, ok = QtGui.QInputDialog.getText(
                self
                , 'Password'
                , 'Enter your password:'
                , QtGui.QLineEdit.Password)
        if ok:
            self.PassWindow = PasswordWindow(
                    hashlib.sha256(text + salt).digest()
                    # letzter teil wird ersetzt durch var aus frickelConfig
                    , os.path.join(os.path.expanduser('~'), "Projects/python/password_sqlite3.db")
                    )
        else:
            print "Und zu?"
            self.closeEvent()
            self.close()

    def closeEvent(self, event):
        print "Jetzt aber oder?"
        reply = QtGui.QMessageBox.question(
                self
                , 'Message'
                , "Are you sure to quit?"
                , QtGui.QMessageBox.Yes | QtGui.QMessageBox.No
                , QtGui.QMessageBox.No
                )
        if reply == QtGui.QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

class PasswordWindow(QtGui.QWidget):

    def __init__(self, password, filename, title="Password Store", width=380, height=400):
        super(PasswordWindow, self).__init__()

        self.title = title
        self.width = width
        self.heigh = height
        self.__crypto = frickelAES_CBC(password, u'12345678abcdefgh')
        
        # Test Foo
        self.__testFuu = "DieKuhLiefUmDenTeich"
        self.__testFoo = self.__crypto.encryptData(self.__testFuu)
        self.__crypto.decryptData(self.__testFoo)
        
        self.__sql = frickelSQLite(filename)
        self.__initUI()

    def __initUI(self):
        self.setGeometry(
                self.width
                , self.width
                , self.width
                , self.heigh
                )
        self.setWindowTitle(self.title)

        ## Menu
        menuPointOpen = QtGui.QAction("Open", self)
        menuPointSave = QtGui.QAction("Save", self)

        menuPointExit = QtGui.QAction("Quit", self)
        menuPointExit.setShortcut('Ctrl+Q')
        menuPointExit.setStatusTip('Exit application')
        menuPointExit.triggered.connect(self.close)

        menuPointHilfe = QtGui.QAction("Hilfe!", self)
        menuPointHilfe.setShortcut('Ctrl+H')
        menuPointHilfe.setStatusTip('Help application')
        menuPointHilfe.triggered.connect(self.__menuHelp)

        menuBar = QtGui.QMenuBar()

        menuFile = menuBar.addMenu("&File")
        menuFile.addAction(menuPointOpen)
        menuFile.addAction(menuPointSave)
        menuFile.addAction(menuPointExit)

        menuHelp = menuBar.addMenu("&Help")
        menuHelp.addAction(menuPointHilfe)

        ## tabss
        tabWidget = QtGui.QTabWidget()

        self.__tab1 = QtGui.QWidget()
        self.__tab2 = QtGui.QWidget()
        self.__tab3 = QtGui.QWidget()
        self.__tab4 = QtGui.QWidget()

        tabWidget.addTab(self.__tab1, u"Liste")
        tabWidget.addTab(self.__tab2, u"Hinzufügen")
        tabWidget.addTab(self.__tab3, u"Löschen")
        tabWidget.addTab(self.__tab4, u"Suchen")

        self.__tabGen1()
        self.__tabGen2()

        verticalBox = QtGui.QVBoxLayout()
        verticalBox.addWidget(menuBar)
        verticalBox.addWidget(tabWidget)
        self.setLayout(verticalBox)

        # signals
        QtCore.QObject.connect(tabWidget, QtCore.SIGNAL('currentChanged(int)'), self.__changeTab)
        QtCore.QObject.connect(self.__okButton, QtCore.SIGNAL('clicked()'), self.__buttonOk)
        QtCore.QObject.connect(self.__clearButton, QtCore.SIGNAL('clicked()'), self.__buttonClear)

        # and action
        self.show()

    def __getDataFromDatabase(self):
        if self.__sql.selectData():
            self.__rowData = self.__sql.selectData()
        else:
            if self.__sql.createTable():
                dataInput = (
                            b64encode(self.__crypto.encryptData(u'some User'))
                            , b64encode(self.__crypto.encryptData(u'some Password'))
                            , b64encode(self.__crypto.encryptData(u'some Description'))
                            )
                self.__sql.insertData(dataInput)
                self.__rowData = self.__sql.selectData()
            else:
                self.__rowData = None

    def __insertDataToDatabase(self):
        dataInput = (
                    b64encode(self.__crypto.encryptData(self.__userInput.text()))
                    ,  b64encode(self.__crypto.encryptData(self.__passInput.text()))
                    ,  b64encode(self.__crypto.encryptData(self.__descInput.toPlainText()))
                    )
        if self.__sql.insertData(dataInput):
            return True
        else:
            return False

    def __changeTab(self, index):
        """
        mal schau, was man hier noch machen kann
        index = int([1-4])
        """
        pass

    def __buttonOk(self):
        error = False
        if not self.__userInput.text():
            if not error:
                error = "Fields empty!"
        if not self.__passInput.text() or not self.__pwvfInput.text():
            if not error:
                error = "Fields empty!"
        elif self.__passInput.text() != self.__pwvfInput.text():
            if not error:
                error = "Password not the same!"
        if not self.__descInput.toPlainText():
            if not error:
                error = "Fields empty!"

        if error:
            self.__statInput.setText(error)
        else:
            # das ist mist ;), wenn ich das schon intern speicher muss ich das auch nicht noch übergeben
            #self._insertDataToDatabase(self._userInput.text(), self._passInput.text(), self._descInput.toPlainText())
            # so ist schöner glaub ich
            if self.__insertDataToDatabase():
                self.__statInput.setText("Done")

                numRows = self.__dataGrid.rowCount()
                self.__dataGrid.insertRow(numRows)

                rowUser = QtGui.QTableWidgetItem(self.__userInput.text())
                rowPass = QtGui.QTableWidgetItem(self.__passInput.text())
                rowDesc = QtGui.QTableWidgetItem(self.__descInput.toPlainText())
                
                self.__dataGrid.setItem(numRows, 0, rowUser)
                self.__dataGrid.setItem(numRows, 1, rowPass)
                self.__dataGrid.setItem(numRows, 2, rowDesc)
            else:
                self.__statInput.setText("SQLite input fail!")

    def __buttonClear(self):
        self.__userInput.setText("")
        self.__passInput.setText("")
        self.__pwvfInput.setText("")
        self.__descInput.setText("")
        self.__statInput.setText("Fields cleared!")

    def __tabGen4(self):
        pass

    def __tabGen3(self):
        pass

    def __tabGen2(self):
        tab2Vertical = QtGui.QGridLayout(self.__tab2)
        tab2Vertical.setSpacing(10)

        userLabel = QtGui.QLabel('Benutzer:')
        passLabel = QtGui.QLabel('Passwort:')
        pwvfLabel = QtGui.QLabel('Passwort Verfication:')
        descLabel = QtGui.QLabel('Bemerkung:')
        statLabel = QtGui.QLabel('Status:')

        self.__userInput = QtGui.QLineEdit()
        self.__passInput = QtGui.QLineEdit()
        self.__passInput.setEchoMode(2)
        self.__pwvfInput = QtGui.QLineEdit()
        self.__pwvfInput.setEchoMode(2)
        self.__descInput = QtGui.QTextEdit()
        self.__statInput = QtGui.QLabel(self)

        self.__okButton = QtGui.QPushButton("OK")
        self.__clearButton = QtGui.QPushButton("Clear")

        tab2Vertical.addWidget(userLabel, 1, 0)
        tab2Vertical.addWidget(self.__userInput, 1, 1)

        tab2Vertical.addWidget(passLabel, 2, 0)
        tab2Vertical.addWidget(self.__passInput, 2, 1)

        tab2Vertical.addWidget(pwvfLabel, 3, 0)
        tab2Vertical.addWidget(self.__pwvfInput, 3, 1)

        tab2Vertical.addWidget(descLabel, 4, 0)
        tab2Vertical.addWidget(self.__descInput, 4, 1, 5, 1)

        tab2Vertical.addWidget(statLabel, 9, 0)
        tab2Vertical.addWidget(self.__statInput, 9, 1)

        tab2Vertical.addWidget(self.__okButton, 10, 0)
        tab2Vertical.addWidget(self.__clearButton, 10, 1)

    def __tabGen1(self):
        self.__getDataFromDatabase()
        headers = ["Benutzer", "Password", "BEMERKUNG"]
        self.__dataGrid = QtGui.QTableWidget()
        self.__dataGrid.setRowCount(len(self.__rowData))
        self.__dataGrid.setColumnCount(len(headers))
        self.__dataGrid.setAlternatingRowColors(True)
        self.__dataGrid.setHorizontalHeaderLabels(headers)
        
        n = 0
        for key in range(n, len(self.__rowData)):
            m = 0
            for item in self.__rowData[key]:
                self.__dataGrid.setItem(
                        n
                        , m
                        , QtGui.QTableWidgetItem(self.__crypto.decryptData(b64decode(item)))
                        )
                m += 1
            n += 1

        # set table width
        self.__dataGrid.resizeColumnsToContents()
        # lösche erste Zeile mit some(User, Passwort und Bemerkung)
        self.__dataGrid.removeRow(0)

        tab1Vertical = QtGui.QVBoxLayout(self.__tab1)
        tab1Vertical.addWidget(self.__dataGrid)

    def __menuHelp(self):
        QtGui.QMessageBox.information(
                self
                , "Dies ist die Hilfe"
                , "Hilf dir selbst, sonst hilft dir keiner!"
                )

    def closeEvent(self, event):
        reply = QtGui.QMessageBox.question(
                self
                , 'Message'
                , "Are you sure to quit?"
                , QtGui.QMessageBox.Yes | QtGui.QMessageBox.No
                , QtGui.QMessageBox.No
                )
        if reply == QtGui.QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

    def keyPressEvent(self, event):
        print(event, event.key())

    def mousePressEvent(self, event):
        print(event, event.key())
 
def main():

    app = QtGui.QApplication(sys.argv)
    pd = PasspharseDialog()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
