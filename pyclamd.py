#!/usr/bin/env python
# -*- coding: utf-8 -*-
#------------------------------------------------------------------------------
# LICENSE:
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free 
# Software  Foundation; either version 3 of the License, or (at your option) any
# later version. See http://www.gnu.org/licenses/lgpl-3.0.txt.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more 
# details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 675 Mass Ave, Cambridge, MA 02139, USA.
#------------------------------------------------------------------------------
# CHANGELOG:
# 2006-07-15 v0.1.1 AN: - released version
# 2007-10-09 v0.2.0 PL: - fixed error with deprecated string exceptions
#					    - added optional timeout to sockets to avoid blocking 
#						  operations
# 2010-07-11 v0.2.1 AN: - change all raise exception (was deprecated), license 
#						  change to LGPL
# 2010-07-12 v0.2.2 TK: - PEP8 compliance
#						  isolating send and receive functions
# 2012-11-20 v0.3.0 AN: - change API to class model
#                       - using INSTREAM scan method instead of the deprecated STREAM
#                       - added MULTISCAN method
#                       - STATS now return full data on multiline
#                   TK: - changes to API to make it more consistent
# 2012-11-20 v0.3.1 AN: - typo change (Connextion to Connexion)
#                       - Fixed Issue 3: scan_stream: AssertionError
# 2013-04-20 v0.3.2 TT/AN: - improving encoding support for non latin filenames
#                   TKL:   - When pyclamd calls _recv_response, it appears to expect
#                            that it will only get one result at a time. This is not
#                            always the case: it may get multiple results separated
#                            by newlines.
#                          - Typos corrected with pyflakes
#                          - Adding a compatibility layer for the most important
#                            functions in the 0.2 API - init_*_socket, scan_file,
#                            contscan_file, multiscan_file, and version.
# 2013-04-21 v0.3.3 AN: - ClamdUnixSocket is now able to get unix socket name
#                         from /etc/clamav/clamd.conf
#------------------------------------------------------------------------------
# TODO:
# - improve tests for Win32 platform (avoid to write EICAR file to disk, or
#   protect it somehow from on-access AV, inside a ZIP/GZip archive isn't enough)
# - use SESSION/END commands to launch several scans in one session
#   (for example provide session mode in a Clamd class)
# - add support for RAWSCAN and MULTISCAN commands ?
# ? Maybe use os.abspath to ensure scan_file uses absolute paths for files
#------------------------------------------------------------------------------
# Documentation : http://www.clamav.net/doc/latest/html/node28.html



"""
pyclamd.py

Author : Alexandre Norman - norman()xael.org
Contributors :
 - PL :  Philippe Lagadec - philippe.lagadec()laposte.net
 - TK :  Thomas Kastner - tk()underground8.com
 - TT :  Theodoropoulos Theodoros (TeD TeD) - sbujam()gmail.com
 - TKL : Thomas Kluyver - thomas () kluyver.me.uk

Licence : LGPL

Usage :

Test strings :
^^^^^^^^^^^^

>>> import pyclamd
>>> try:
...     cd = pyclamd.ClamdUnixSocket()
...     # test if server is reachable
...     cd.ping()
... except pyclamd.ConnectionError:
...     # if failed, test for network socket
...     cd = pyclamd.ClamdNetworkSocket()
...     try:
...         cd.ping()
...     except pyclamd.ConnectionError:
...         raise ValueError('could not connect to clamd server either by unix or network socket')
True
>>> print(cd.version().split()[0])
ClamAV
>>> print(cd.reload())
RELOADING
>>> print(cd.stats().split()[0])
POOLS:
>>> void = open('/tmp/EICAR','w').write(cd.EICAR())
>>> void = open('/tmp/NO_EICAR','w').write('no virus in this file')
>>> cd.scan_file('/tmp/EICAR')['/tmp/EICAR']
('FOUND', 'Eicar-Test-Signature')
>>> cd.scan_file('/tmp/NO_EICAR') is None
True
>>> cd.scan_stream(cd.EICAR())['stream']
('FOUND', 'Eicar-Test-Signature')
>>> directory = cd.contscan_file('/tmp/')
>>> directory['/tmp/EICAR']
('FOUND', 'Eicar-Test-Signature')
>>> # Testing encoding with non latin characters (Chinese ideograms taken from random site, don't know what it mean, sorry)
>>> void = open('/tmp/EICAR-éèô请收藏我们的网址','w').write(cd.EICAR())
>>> r = cd.scan_file('/tmp/EICAR-éèô请收藏我们的网址')
>>> print(list(r.keys())[0])
/tmp/EICAR-éèô请收藏我们的网址
>>> print(r['/tmp/EICAR-éèô请收藏我们的网址'])
('FOUND', 'Eicar-Test-Signature')
>>> import os
>>> os.remove('/tmp/EICAR')
>>> os.remove('/tmp/NO_EICAR')
>>> os.remove('/tmp/EICAR-éèô请收藏我们的网址')
"""



__version__ = "0.3.3"
# $Source$


import socket
import struct
import base64

############################################################################

class BufferTooLongError(ValueError):
    """Class for errors with clamd using INSTREAM with a buffer lenght > StreamMaxLength in /etc/clamav/clamd.conf"""


class ConnectionError(socket.error):
    """Class for errors communication with clamd"""



############################################################################


class _ClamdGeneric(object):
    """
    Abstract class for clamd
    """
    
    def EICAR(self):
        """
        returns Eicar test string
        """
        # Eicar test string (encoded for skipping virus scanners)
        
        EICAR = base64.b64decode('WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=\n'.encode('ascii')).decode('ascii')
        return EICAR
        

    def ping(self):
        """
        Send a PING to the clamav server, which should reply
        by a PONG.

        return: True if the server replies to PING

        May raise:
          - ConnectionError: if the server do not reply by PONG
        """

        self._init_socket()

        try:
            self._send_command('PING')
            result = self._recv_response()
            self._close_socket()
        except socket.error:
            raise ConnectionError('Could not ping clamd server')

        if result == 'PONG':
            return True
        else:
            raise ConnectionError('Could not ping clamd server [{0}]'.format(result))
        return


    
    def version(self):
        """
        Get Clamscan version

        return: (string) clamscan version

        May raise:
          - ConnectionError: in case of communication problem
        """
        self._init_socket()
        try:
            self._send_command('VERSION')
            result = self._recv_response()
            self._close_socket()
        except socket.error:
            raise ConnectionError('Could not get version information from server')

        return result


    def stats(self):
        """
        Get Clamscan stats

        return: (string) clamscan stats

        May raise:
          - ConnectionError: in case of communication problem
        """
        self._init_socket()
        try:
            self._send_command('STATS')
            result = self._recv_response_multiline()
            self._close_socket()
        except socket.error:
            raise ConnectionError('Could not get version information from server')

        return result

    
    def reload(self):
        """
        Force Clamd to reload signature database

        return: (string) "RELOADING"

        May raise:
          - ConnectionError: in case of communication problem
        """


        try:
            self._init_socket()
            self._send_command('RELOAD')
            result = self._recv_response()
            self._close_socket()
            
        except socket.error:
            raise ConnectionError('Could probably not reload signature database')

        return result


    
    def shutdown(self):
        """
        Force Clamd to shutdown and exit

        return: nothing

        May raise:
          - ConnectionError: in case of communication problem
        """
        try:
            self._init_socket()
            self._send_command('SHUTDOWN')
            self._recv_response()
            self._close_socket()
        except socket.error:
            raise ConnectionError('Could probably not shutdown clamd')


    
    def scan_file(self, file):
        """
        Scan a file or directory given by filename and stop on first virus or error found.
        Scan with archive support enabled.

        file (string) : filename or directory (MUST BE ABSOLUTE PATH !)

        return either :
          - (dict): {filename1: "virusname"}
          - None: if no virus found

        May raise :
          - ConnectionError: in case of communication problem
          - socket.timeout: if timeout has expired
        """

        assert isinstance(file, str), 'Wrong type for [file], should be a string [was {0}]'.format(type(file))

        try:
            self._init_socket()
            self._send_command('SCAN {0}'.format(file))
        except socket.error:
            raise ConnectionError('Unable to scan {0}'.format(file))

        result='...'
        dr={}
        while result:
            try:
                result = self._recv_response()
            except socket.error:
                raise ConnectionError('Unable to scan {0}'.format(file))

            if len(result) > 0:
                filename, reason, status = self._parse_response(result)

                if status == 'ERROR':
                    dr[filename] = ('ERROR', '{0}'.format(reason))
                    return dr
                    
                elif status == 'FOUND':
                    dr[filename] = ('FOUND', '{0}'.format(reason))

        self._close_socket()
        if not dr:
            return None
        return dr

    



    def multiscan_file(self, file):
        """
        Scan a file or directory given by filename using multiple threads (faster on SMP machines).
        Do not stop on error or virus found.
        Scan with archive support enabled.

        file (string): filename or directory (MUST BE ABSOLUTE PATH !)

        return either :
          - (dict): {filename1: ('FOUND', 'virusname'), filename2: ('ERROR', 'reason')}
          - None: if no virus found

        May raise:
          - ConnectionError: in case of communication problem
        """
        assert isinstance(file, str), 'Wrong type for [file], should be a string [was {0}]'.format(type(file))

        try:
            self._init_socket()
            self._send_command('MULTISCAN {0}'.format(file))
        except socket.error:
            raise ConnectionError('Unable to scan {0}'.format(file))

        result='...'
        dr={}
        while result:
            try:
                result = self._recv_response()
            except socket.error:
                raise ConnectionError('Unable to scan {0}'.format(file))

            if len(result) > 0:
                for resline in result.splitlines():
                    filename, reason, status = self._parse_response(resline)

                    if status == 'ERROR':
                        dr[filename] = ('ERROR', '{0}'.format(reason))
                    
                    elif status == 'FOUND':
                        dr[filename] = ('FOUND', '{0}'.format(reason))

        self._close_socket()
        if not dr:
            return None
        return dr







    def contscan_file(self, file):
        """
        Scan a file or directory given by filename
        Do not stop on error or virus found.
        Scan with archive support enabled.

        file (string): filename or directory (MUST BE ABSOLUTE PATH !)

        return either :
          - (dict): {filename1: ('FOUND', 'virusname'), filename2: ('ERROR', 'reason')}
          - None: if no virus found

        May raise:
          - ConnectionError: in case of communication problem
        """
        assert isinstance(file, str), 'Wrong type for [file], should be a string [was {0}]'.format(type(file))

        try:
            self._init_socket()
            self._send_command('CONTSCAN {0}'.format(file))
        except socket.error:
            raise ConnectionError('Unable to scan  {0}'.format(file))

        result='...'
        dr={}
        while result:
            try:
                result = self._recv_response()
            except socket.error:
                raise ConnectionError('Unable to scan  {0}'.format(file))

            if len(result) > 0:
                for resline in result.splitlines():
                    filename, reason, status = self._parse_response(resline)
                    
                    if status == 'ERROR':
                        dr[filename] = ('ERROR', '{0}'.format(reason))
                    
                    elif status == 'FOUND':
                        dr[filename] = ('FOUND', '{0}'.format(reason))

        self._close_socket()
        if not dr:
            return None
        return dr



    def scan_stream(self, buffer_to_test):
        """
        Scan a buffer

        buffer_to_test (string): buffer to scan

        return either:
          - (dict): {filename1: "virusname"}
          - None: if no virus found

        May raise :
          - BufferTooLongError: if the buffer size exceeds clamd limits
          - ConnectionError: in case of communication problem
        """
        try:
            self._init_socket()
            self._send_command('INSTREAM')

            max_chunk_size = 1024 # MUST be < StreamMaxLength in /etc/clamav/clamd.conf

            chunks_left = buffer_to_test
            while len(chunks_left)>0:
                chunk = chunks_left[:max_chunk_size]
                chunks_left = chunks_left[max_chunk_size:]

                size = bytes.decode(struct.pack('!L', len(chunk)))
                self.clamd_socket.send(str.encode('{0}{1}'.format(size, chunk)))

            self.clamd_socket.send(struct.pack('!L', 0))
                
            
        except socket.error:
            raise ConnectionError('Unable to scan stream')


        result='...'
        dr={}
        while result:
            try:
                result = self._recv_response()
            except socket.error:
                raise ConnectionError('Unable to scan stream')

            if len(result) > 0:
                
                if result == 'INSTREAM size limit exceeded. ERROR':
                    raise BufferTooLongError(result)

                filename, reason, status = self._parse_response(result)
               
                if status == 'ERROR':
                    dr[filename] = ('ERROR', '{0}'.format(reason))
                    
                elif status == 'FOUND':
                    dr[filename] = ('FOUND', '{0}'.format(reason))

        self._close_socket()
        if not dr:
            return None
        return dr





    
    def _send_command(self, cmd):
        """
        `man clamd` recommends to prefix commands with z, but we will use \n
        terminated strings, as python<->clamd has some problems with \0x00
        """
        try:
            cmd = str.encode('n{0}\n'.format(cmd))
        except UnicodeDecodeError:
            cmd = 'n{0}\n'.format(cmd)
        self.clamd_socket.send(cmd)
        return

    

    def _recv_response(self):
        """
        receive response from clamd and strip all whitespace characters
        """
        data = self.clamd_socket.recv(4096)
        try:
            response = bytes.decode(data).strip()
        except UnicodeDecodeError:
            response = data.strip()

        return response



    def _recv_response_multiline(self):
        """
        receive multiple line response from clamd and strip all whitespace characters
        """
        response = ''
        c = '...'
        while c != '':
            try:
                data = self.clamd_socket.recv(4096)
                try:
                    c = bytes.decode(data).strip()
                except UnicodeDecodeError:
                    response = data.strip()
            except socket.error:
                break
                
            response += '{0}\n'.format(c)
        return response



    def _close_socket(self):
        """
        close clamd socket
        """
        self.clamd_socket.close()
        return
    

    def _parse_response(self, msg):
        """
        parses responses for SCAN, CONTSCAN, MULTISCAN and STREAM commands.
        """
        msg = msg.strip()
        filename = msg.split(': ')[0]
        left = msg.split(': ')[1:]
        if isinstance(left, str):
            result = left
        else:
            result = ": ".join(left)
            
        if result != 'OK':
            parts = result.split()
            reason = ' '.join(parts[:-1])
            status = parts[-1]
        else:
            reason, status = '', 'OK'


        return filename, reason, status




############################################################################


class ClamdUnixSocket(_ClamdGeneric):
    """
    Class for using clamd with an unix socket
    """
    def __init__(self, filename=None, timeout=None):
        """
        Unix Socket Class initialisation
        
        filename (string) : unix socket filename or None to get the socket from /etc/clamav/clamd.conf
        timeout (float or None) : socket timeout
        """

        # try to get unix socket from clamd.conf
        if filename is None:
            with open('/etc/clamav/clamd.conf', 'r') as conffile:
                for line in conffile.readlines():
                    try:
                        if line.strip().split()[0] == 'LocalSocket':
                            filename = line.strip().split()[1]
                            break
                    except IndexError:
                        pass
                            
                else:
                    raise ConnectionError('Could not find clamd unix socket from /etc/clamav/clamd.conf')
        
        assert isinstance(filename, str), 'Wrong type for [file], should be a string [was {0}]'.format(type(file))
        assert isinstance(timeout, (float, int)) or timeout is None, 'Wrong type for [timeout], should be either None or a float [was {0}]'.format(type(timeout))

        _ClamdGeneric.__init__(self)
        
        self.unix_socket = filename
        self.timeout = timeout

        # tests the socket
        self._init_socket()
        self._close_socket()

        return


    def _init_socket(self):
        """
        internal use only
        """
        try:
            self.clamd_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.clamd_socket.connect(self.unix_socket)
            self.clamd_socket.settimeout(self.timeout)
        except socket.error:
            raise ConnectionError('Could not reach clamd using unix socket ({0})'.format((self.unix_socket)))
        return
    

############################################################################


class ClamdNetworkSocket(_ClamdGeneric):
    """
    Class for using clamd with a network socket
    """
    def __init__(self, host='127.0.0.1', port=3310, timeout=None):
        """
        Network Class initialisation
        host (string) : hostname or ip address
        port (int) : TCP port
        timeout (float or None) : socket timeout
        """
            
        assert isinstance(host, str), 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        assert isinstance(port, int), 'Wrong type for [port], should be an int [was {0}]'.format(type(port))
        assert isinstance(timeout, (float, int)) or timeout is None, 'Wrong type for [timeout], should be either None or a float [was {0}]'.format(type(timeout))
        
        _ClamdGeneric.__init__(self)
        
        self.host = host
        self.port = port
        self.timeout = timeout

        # tests the socket
        self._init_socket()
        self._close_socket()

        return


    def _init_socket(self):
        """
        internal use only
        """
        try:
            self.clamd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.clamd_socket.connect((self.host, self.port))
            self.clamd_socket.settimeout(self.timeout)

        except socket.error:
            raise ConnectionError('Could not reach clamd using network ({0}, {1})'.format(self.host, self.port))

        return

    

############################################################################


# Backwards compatibility API ##############################################

socketinst = None

def init_network_socket(host='127.0.0.1', port=3310, timeout=None):
    """Deprecated API - use ClamdNetworkSocket instead."""
    global socketinst
    socketinst = ClamdNetworkSocket(host=host, port=port, timeout=timeout)

def init_unix_socket(filename=None):
    """Deprecated API - use ClamdUnixSocket instead."""
    global socketinst
    socketinst = ClamdUnixSocket(filename=filename)

def _needs_socket(func):
    """Decorator to check that the global socket is initialised."""
    def wrapper(*args, **kw):
        if socketinst is None:
            raise ConnectionError('socket not initialised')
        return func(*args, **kw)
    wrapper.__doc__ = func.__doc__
    return wrapper

@_needs_socket
def scan_file(file):
    """Deprecated API - use one of the Clamd*Socket classes instead."""
    return socketinst.scan_file(file)

@_needs_socket
def contscan_file(file):
    """Deprecated API - use one of the Clamd*Socket classes instead."""
    return socketinst.contscan_file(file)

@_needs_socket
def multiscan_file(file):
    """Deprecated API - use one of the Clamd*Socket classes instead."""
    return socketinst.multiscan_file(file)

@_needs_socket
def version():
    """Deprecated API - use one of the Clamd*Socket classes instead."""
    return socketinst.version()

############################################################################


def _non_regression_test():
	"""
	This is for internal use
	"""
	import doctest
	doctest.testmod()
	return
	

############################################################################


def _print_doc():
    """
    This is for internal use
    """
    import os
    os.system('pydoc ./{0}.py'.format(__name__))
    return


# MAIN -------------------
if __name__ == '__main__':

    _non_regression_test()


#<EOF>###########################################################################
