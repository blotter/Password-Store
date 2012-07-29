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
from Crypto.Cipher import AES
from PyQt4 import QtGui
from PyQt4 import QtCore
from base64 import b64encode
from base64 import b64decode

class frickelAES_CBC(object):
    def __init__(self, password, initialvector):
        self.blockSize = 32
        self.interrupt = u'\u0001'
        self.pad = u'\u0000'

        self.initCrypto(password,  initialVector)

    def initCrypto(self, password, initialVector):
        self._cipherForEncryption = AES.new(password, AES.MODE_CBC, initialVector)
        self._cipherForDecryption = AES.new(password, AES.MODE_CBC, initialVector)

    def __addPadding(self, data):
        _newData = ''.join([data, interrupt])
        _newDataLen = len(_newData)
        _remainingLen = self.blockSize - _newDataLen
        _toPadLen = _remainingLen % self.blockSize
        _padString = self.pad * _toPadLen
        return ''.join([_newData, _padString])

    def __stripPadding(self, data):
        try:
            return data.rstrip(self.pad).rstrip(self.interrupt)
        except UnicodeDecodeError, e:
            print e
            return None

    def encryptData(self, plaintextData):
        _plaintextPadded = self.__addPadding(plaintextData)
        _encryptedData = self._cipherForEncryption.encrypt(_plaintextPadded)
        return _encryptedData


    def decryptData(self, encryptedData):
        _decryptedData = self._cipherForDecryption.decrypt(encryptedData)
        return self.__stripPadding(_decryptedData)

class frickelSQLite(object):
    def __init__(self, filename):
        self.sqlite = sqlite3.connect(filename)

    def selectData(self):
        """
        ToDo:
            * selectData need SQL select per input
        """
        _sqliteSelect = '''
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
            conn = self.sqlite.cursor()
            _rows = conn.execute(_sqliteSelect)
        except:
            """
            ToDo:
                * better error handling
                    * sqlite3.OperationalError
            """
            error = False
            
        else:
            error = _rows.fetchall()
        finally:
            if conn:
                conn.close()
            return error
   
    def insertData(self,  data):        
        try: 
            conn = self.sqlite.cursor()
            conn.execute("INSERT INTO password VALUES (NULL,?,?,?)", data)
            self.sqlite.commit()
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

    def deleteData(self, id):
        pass
        
    def createTable(self):
        try:
            conn = self.sqlite.cursor()
            conn.execute('''CREATE TABLE password
                    (id INTEGER PRIMARY KEY, Benutzer TEXT, Passwort TEXT, Bemerkung TEXT)''')
            self.sqlite.commit()
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
                    , '/home/janus/Projects/python/password_sqlite3.db'
                    #, '~/password_sqlite3.db'
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
        self.crypto = frickelAES_CBC(password,  u'12345678abcdefgh')
        self.sql = frickelSQLite(filename)
        self.initUI()

    def initUI(self):
        self.setGeometry(
                self.width
                , self.width
                , self.width
                , self.heigh
                )
        self.setWindowTitle(self.title)

        ## Menu
        _open = QtGui.QAction("Open", self)
        _save = QtGui.QAction("Save", self)

        _exit = QtGui.QAction("Quit", self)
        _exit.setShortcut('Ctrl+Q')
        _exit.setStatusTip('Exit application')
        _exit.triggered.connect(self.close)

        _hilfe = QtGui.QAction("Hilfe!", self)
        _hilfe.setShortcut('Ctrl+H')
        _hilfe.setStatusTip('Help application')
        _hilfe.triggered.connect(self._menuHelp)

        _menuBar = QtGui.QMenuBar()

        _file = _menuBar.addMenu("&File")
        _file.addAction(_open)
        _file.addAction(_save)
        _file.addAction(_exit)

        _help = _menuBar.addMenu("&Help")
        _help.addAction(_hilfe)

        ## tabss
        _tabWidget = QtGui.QTabWidget()

        self._tab1 = QtGui.QWidget()
        self._tab2 = QtGui.QWidget()
        self._tab3 = QtGui.QWidget()
        self._tab4 = QtGui.QWidget()

        _tabWidget.addTab(self._tab1, u"Liste")
        _tabWidget.addTab(self._tab2, u"Hinzufügen")
        _tabWidget.addTab(self._tab3, u"Löschen")
        _tabWidget.addTab(self._tab4, u"Suchen")

        self._tabGen1()
        self._tabGen2()

        _vbox = QtGui.QVBoxLayout()
        _vbox.addWidget(_menuBar)
        _vbox.addWidget(_tabWidget)
        self.setLayout(_vbox)

        # signals
        QtCore.QObject.connect(_tabWidget, QtCore.SIGNAL('currentChanged(int)'), self._changeTab)
        QtCore.QObject.connect(self._okButton, QtCore.SIGNAL('clicked()'), self._buttonOk)
        QtCore.QObject.connect(self._clearButton, QtCore.SIGNAL('clicked()'), self._buttonClear)

        # and action
        self.show()

    def _changeTab(self, index):
        """
        mal schau, was man hier noch machen kann
        """
        if index == 0:
            pass
        elif index == 1:
            pass
        elif index == 2:
            pass
        elif index == 3:
            pass
        else:
            print "Hier stimmt was nicht :D!"


    def _buttonOk(self):
        _error = ""
        if not self._userInput.text():
            if not _error:
                _error = "Fields empty!"
        if not self._passInput.text() or not self._pwvfInput.text():
            if not _error:
                _error = "Fields empty!"
        elif self._passInput.text() != self._pwvfInput.text():
            if not _error:
                _error = "Password not the same!"
        if not self._descInput.toPlainText():
            if not _error:
                _error = "Fields empty!"

        if _error:
            self._statInput.setText(_error)
        else:
            # das ist mist ;), wenn ich das schon intern speicher muss ich das auch nicht noch übergeben
            #self._insertDataToDatabase(self._userInput.text(), self._passInput.text(), self._descInput.toPlainText())
            # so ist schöner glaub ich
            self._insertDataToDatabase()

    def _buttonClear(self):
        self._userInput.setText("")
        self._passInput.setText("")
        self._pwvfInput.setText("")
        self._descInput.setText("")
        self._statInput.setText("Fields cleared!")

    def _tabGen4(self):
        pass

    def _tabGen3(self):
        pass

    def _tabGen2(self):
        self._tab2Vertical = QtGui.QGridLayout(self._tab2)
        self._tab2Vertical.setSpacing(10)

        _userLabel = QtGui.QLabel('Benutzer:')
        _passLabel = QtGui.QLabel('Passwort:')
        _pwvfLabel = QtGui.QLabel('Passwort Verfication:')
        _descLabel = QtGui.QLabel('Bemerkung:')
        _statLabel = QtGui.QLabel('Status:')

        self._userInput = QtGui.QLineEdit()
        self._passInput = QtGui.QLineEdit()
        self._passInput.setEchoMode(2)
        self._pwvfInput = QtGui.QLineEdit()
        self._pwvfInput.setEchoMode(2)
        self._descInput = QtGui.QTextEdit()
        self._statInput = QtGui.QLabel(self)

        self._okButton = QtGui.QPushButton("OK")
        self._clearButton = QtGui.QPushButton("Clear")

        self._tab2Vertical.addWidget(_userLabel, 1, 0)
        self._tab2Vertical.addWidget(self._userInput, 1, 1)

        self._tab2Vertical.addWidget(_passLabel, 2, 0)
        self._tab2Vertical.addWidget(self._passInput, 2, 1)

        self._tab2Vertical.addWidget(_pwvfLabel, 3, 0)
        self._tab2Vertical.addWidget(self._pwvfInput, 3, 1)

        self._tab2Vertical.addWidget(_descLabel, 4, 0)
        self._tab2Vertical.addWidget(self._descInput, 4, 1, 5, 1)

        self._tab2Vertical.addWidget(_statLabel, 9, 0)
        self._tab2Vertical.addWidget(self._statInput, 9, 1)

        self._tab2Vertical.addWidget(self._okButton, 10, 0)
        self._tab2Vertical.addWidget(self._clearButton, 10, 1)

    def _tabGen1(self):
        self._getDataFromDatabase()
        _rows = self._sqliteData

        _headers = ["Benutzer", "Password", "BEMERKUNG"]
        self._dataGrid = QtGui.QTableWidget()
        self._dataGrid.setRowCount(len(_rows))
        self._dataGrid.setColumnCount(len(_headers))
        self._dataGrid.setAlternatingRowColors(True)
        self._dataGrid.setHorizontalHeaderLabels(_headers)
        
        n = 0
        for key in range(0, len(_rows)):
            m = 0
            for item in _rows[key]:
                self._dataGrid.setItem(
                        n
                        , m
                        , QtGui.QTableWidgetItem(self._decryptDataAES(self._cipherForEncryption, item))
                        )
                m += 1
            n += 1

        # set table width
        self._dataGrid.resizeColumnsToContents()

        self._tab1Vertical = QtGui.QVBoxLayout(self._tab1)
        self._tab1Vertical.addWidget(self._dataGrid)

    def _menuHelp(self):
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
