# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
#
#    This file is part of LinOTP userid resolvers.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
#    Module Author : Hamid Maadani
#    E-mail: hamid@dexo.tech
#    Contact: hamid.maadani.com
#
"""This module implements the communication interface
   for resolvin user info to a mongodb user base

MongoResolver.IdResolver class
    implements the UserIdResolver for mongodb lookup

"""

import os
import re
import logging
import pymongo

from . import resolver_registry

from UserIdResolver import UserIdResolver
from UserIdResolver import ResolverLoadConfigError
from UserIdResolver import getResolverClass

from linotp.lib.type_utils import text

log = logging.getLogger(__name__)


#def str2unicode(input_str):
    #"""
    #convert as binary string into a unicode string by trying various encodings
    #:param input_str: input binary string
    #:return: unicode output
    #"""

    #output_str = input_str
    #conversions = [{},
                   #{'encoding':'utf-8'},
                   #{'encoding':'iso-8859-1'},
                   #{'encoding':'iso-8859-15'}
                   #]
    #for param in conversions:
        #try:
            #output_str = unicode(input_str, **param)
            #break
        #except UnicodeDecodeError as exx:
            #if param == conversions[-1]:
                #log.info('no unicode conversion found for %r' % input_str)
                #raise exx

    #return output_str


#def tokenise(r):
    #def _(s):
        #ret = None
        #st = s.strip()
        #m = re.match("^" + r, st)
        #if m:
            #ret = (st[:m.end()].strip(), st[m.end():].strip())
            ##ret[0].strip()      ## remove ws
            ##ret[1].strip()
        #return ret
    #return _


@resolver_registry.class_entry('useridresolver.MongoResolver.IdResolver')
@resolver_registry.class_entry('useridresolveree.MongoResolver.IdResolver')
@resolver_registry.class_entry('useridresolver.mongoresolver')
@resolver_registry.class_entry('mongoresolver')
class IdResolver (UserIdResolver):

    db_prefix = 'useridresolver.MongoResolver.IdResolver'

    fields = {"username": 1, "userid": 1,
              "description": 0,
              "phone": 0, "mobile": 0, "email": 0,
              "givenname": 0, "surname": 0, "gender": 0
              }

    searchFields = {
          "username": "text",
          "email": "text"
    }

    resolver_parameters = {
        "collection": (True, None, text),
        "connString": (True, None, text),
        'linotp.root': (False, None, text)
    }
    resolver_parameters.update(UserIdResolver.resolver_parameters)

    @classmethod
    def setup(cls, config=None, cache_dir=None):
        '''
        this setup hook is triggered, when the server
        starts to serve the first request

        :param config: the linotp config
        :type  config: the linotp config dict
        '''
        log.info("Setting up the MongoResolver")
        return

    def __init__(self):
        """
        simple constructor
        """
        self.name = "mongo"
        self.collection = ""
        self.connString = ""

        self.client = None
        self.db = None
        self.coll = None

    def close(self):
        """
        request hook - to close down resolver object
        """
        return

    def getConnection(self):

        """
          init gets a connection to MongoDB for
            user loginname lookup
        """

        if (self.connString == ""):
            self.connString = ""

        if (self.collection == ""):
            self.collection = "auth"

        log.info('[getConnection] connecting to %s ' % (self.connString))

        self.client = pymongo.MongoClient(self.connString)
        db = self.client.get_default_database()
        self.coll = db[self.collection]

    def checkPass(self, uname, password):
        """
        This function checks the password for a given username.
        - returns true in case of success
        -         false if password does not match
        """
        import hashlib

        if type(password) is unicode:
            log.debug("Password is a unicode string. Encoding to UTF-8 for hashlib.sha256() function.")
            password = password.encode('utf-8')
        log.info("[checkPass] checking password for user %s" % uname)
        passHash = hashlib.sha256().update(password).hexdigest()
        log.debug("[checkPass] pass sah256 hash is %s" % passHash)
        user = self.coll.find_one({"username":uname, "password":passHash})
        if user:
            log.info("[checkPass] successfully authenticated user %s" % uname)
            return True
        else:
            log.warning("[checkPass] Failed to verify password for %s!" % uname)
            return False

    def getUserInfo(self, uname, no_passwd=False):
        """
        get some info about the user

        :param uname: the to be searched user
        :param no_passwd: retrun no password
        :return: dict of user info
        """
        ret = {}

        user = self.coll.find_one({"username":uname})

        ret['username'] = user.username
        ret['givenname'] = user.firstname
        ret['surname'] = user.lastname
        ret['phone'] = user.phone
        ret['email'] = user.email

        return ret

    def getUsername(self, uname):
        '''
        :param userId: the user to be searched
        :return: true, if a user id exists
        '''
        user = self.coll.find_one({"username":uname})
        if user:
            return True
        else:
            return False

    def getSearchFields(self, searchDict=None):
        """
        show, which search fields this userIdResolver supports

        TODO: implementation is not completed

        :param searchDict: fields, which should be queried
        :return: dict of all searchFields
        """
        if searchDict != None:
            for search in searchDict:
                pattern = searchDict[search]

                log.debug("[getSearchFields] searching for %s:%s",
                          search, pattern)

        return self.searchFields

    def getUserList(self):
        """
        get a list of all users
        """
        ret = []
        users = self.coll.find({})

        ##  first check if the searches are in the searchDict
        for u in users:
            ret.append(u.username)

        return ret

#############################################################
# server info methods
#############################################################

    def getResolverId(self):
        """ getResolverId(LoginName)
            - returns the resolver identifier string
            - empty string if not exist
        """
        return self.name

    @classmethod
    def getResolverClassType(cls):
        return 'mongoresolver'

    def getResolverType(self):
        return IdResolver.getResolverClassType()

    @classmethod
    def getResolverClassDescriptor(cls):
        '''
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        '''
        descriptor = {}
        typ = cls.getResolverClassType()
        descriptor['clazz'] = "useridresolver.MongoResolver.IdResolver"
        descriptor['config'] = {'collection': 'string', 'connString': 'string'}
        return {typ: descriptor}

    def getResolverDescriptor(self):
        return IdResolver.getResolverClassDescriptor()

    def loadConfig(self, config, conf):
        """ loadConfig(configDict)
            The UserIdResolver could be configured
            from the pylon app config
        """

        l_config, missing = self.filter_config(config, conf)

        if missing:
            log.error("missing config entries: %r", missing)
            raise ResolverLoadConfigError(" missing config entries: %r" % missing)

        self.collection = l_config["collection"]
        self.connString = l_config["connString"]

        self.getConnection()

        return self

if __name__ == "__main__":

    print " MongoResolver - IdResolver class for MongoDB "
    print None
