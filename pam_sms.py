# -*- coding: utf-8 -*-

'''
A SMS authentication module.

storage: redis
redis_values:
    <prefix>:users: hashtable, 'proton' -> 18612748499 pairs
    <prefix>:success:<username>: str, has ttl, indicates <username> has a success authentication in grace period.

module arguments:
    redis=localhost
    redis_port=6379
    redis_db=0
    prefix=pam_sms  # redis key prefix
    grace_period=4800  # no verification if last success is in grace_period seconds
    absent_ok=0  # set to 1 if you want users not in the 'users' list to authenticate
    sms_user=user
    sms_passwd=passwd
'''

import redis
import random
import urllib
import urllib2


DEFAULT_ARGUMENTS = {
    'redis': 'localhost',
    'redis_port': '6379',
    'redis_db': '0',
    'prefix': 'pam_sms',
    'grace_period': '4800',
    'absent_ok': '0',
    'sms_user': 'user',
    'sms_passwd': 'passwd',
}


SENDSMS_URL = "http://si.800617.com:4400/SendLenSms.aspx"


def send_sms(username, passwd, phone, vcode):
    msg = 'Zhihu server code: %s' % vcode
    request_headers = {'un': username, 'pwd': passwd, 'mobile': phone, 'msg': msg}
    params = urllib.urlencode(request_headers)
    urllib2.urlopen(SENDSMS_URL, params)


def parse_args(argv):
    args = dict(DEFAULT_ARGUMENTS)
    for s in argv[1:]:
        l = s.split('=', 1)
        if len(l) == 1:
            args[l[0]] = ''
        else:
            args[l[0].strip()] = l[1].strip()

    return args


def message(pamh, msg):
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, msg))


def error(pamh, msg):
    pamh.conversation(pamh.Message(pamh.PAM_ERROR_MSG, msg))


def pam_sm_authenticate(pamh, flags, argv):
    user = pamh.get_user()
    if not user:
        error(pamh, "pam_sms: Can't get user, not do authenticating")
        return pamh.PAM_IGNORE

    args = parse_args(argv)
    absent_ok = int(args['absent_ok'])
    grace_period = int(args['grace_period'])
    prefix = args['prefix']
    sms_user = args['sms_user']
    sms_passwd = args['sms_passwd']

    store = redis.Redis(host=args['redis'], port=int(args['redis_port']), db=int(args['redis_db']))

    phone = store.hget('%s:users' % prefix, user)
    message(pamh, '%r %r' % (prefix, phone))
    if not phone:
        if absent_ok:
            message('pam_sms: not authenticating: user "%s" not registered' % user)
            return pamh.PAM_SUCCESS
        else:
            error(pamh, 'pam_sms: user "%s" not registered' % user)
            return pamh.PAM_AUTH_ERR

    is_grace = store.get('%s:success:%s' % (prefix, user))
    if is_grace:
        return pamh.PAM_SUCCESS

    vcode = random.randint(100000, 1000000)
    message(pamh, 'pam_sms: Sending verification code, please wait...')

    try:
        send_sms(sms_user, sms_passwd, phone, vcode)
    except:
        error(pamh, "Can't send sms, not authenticating.")
        return pamh.PAM_SUCCESS

    for _ in xrange(3):
        entered = pamh.conversation(pamh.Message(
            pamh.PAM_PROMPT_ECHO_OFF,
            'Code: '
        )).resp

        try:
            entered = int(entered)
        except:
            entered = 0

        if entered == vcode:
            k = '%s:success:%s' % (prefix, user)
            store.set(k, '1')
            store.expire(k, grace_period)
            return pamh.PAM_SUCCESS
        else:
            error(pamh, 'Wrong code')
    else:
        return pamh.PAM_AUTH_ERR


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS
