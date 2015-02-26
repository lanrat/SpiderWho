'''Python module to contain all configuration settings for SpiderWho'''

'''Debug Mode'''
DEBUG = False

''' When printing display DPS or LPS '''
DPS = True

'''Enable checking result with EMAIL_REGEX'''
RESULT_VALIDCHECK = False

'''Regex used for whois validation when email check is enabled'''
EMAIL_REGEX = r'[\w.-]+@[\w.-]+'

'''Skip domains that already have a result saved'''
SKIP_DONE = False

'''Enable printing of status output'''
PRINT_STATUS = True

'''Enable logging'''
SAVE_LOGS = False

'''Enable lazy mode'''
LAZY_MODE = False

'''Folders to use for output'''
OUTPUT_FOLDER = "out/"
RESULTS_FOLDER = "results/"
LOG_FOLDER = "logs/"

'''Name of file to place domains that failed'''
FAIL_FILENAME = "fail.txt"

'''File extensions'''
SAVE_EXT = "whois"
LOG_EXT = "log"

'''Maximum number of proxies/threads to use, 0=All'''
NUM_PROXIES = 0

'''Maximum size of queues, when the queues reach their max size they will block new items until items are removed'''
MAX_QUEUE_SIZE = 10000

'''Minimum number of lines of response required for it to be considered valid'''
MIN_RESPONSE_LINES = 4

'''When a result fails for any reason, retry it'''
'''setting this value to less than 2 will greatly reduce the reliability of the program'''
MAX_ATTEMPTS = 3

'''Amount of seconds to wait when updating output (float)'''
STATUS_UPDATE_DELAY = 1.0

'''Amount of seconds to wait between using the same whois server per proxy'''
WHOIS_SERVER_JUMP_DELAY = 10

'''Minimum seconds to sleep when waiting for a JUMP_DELAY'''
WHOIS_SERVER_SLEEP_DELAY = 5

'''Amount of seconds to give each whois query before failing'''
WHOIS_TIMEOUT_SECONDS = 10

'''Amount of seconds to wait before trying to reconnect to a failed proxy'''
PROXY_FAIL_RECONNECT_DELAY = 20

''' How many minutes to wait before trimming whois history '''
WHOIS_HISTORY_TRIM_MINUTES = 15

''' Saves the tar.gz output format '''
SAVE_TAR = True

''' Numer of results to put in tar file befor rotating '''
SAVE_TAR_SIZE = 500000

'''
list of servers who are known to be VERY strict with whois data
TODO currently unused
'''
STRICT_SERVERS = [
       "org.whois-servers.net",
       "whois.godaddy.com"
        ]

'''Placeholders, set at runtime'''
DOMAIN_LIST = None
PROXY_LIST = None
START_TIME = 0
SKIP_DOMAINS = 0
