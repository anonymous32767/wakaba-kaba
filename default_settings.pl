our $default_settings = {
	# Page look
	TITLE => "Wakaba image board",
	SHOWTITLETXT => 1,
	SHOWTITLEIMG => 0,
	TITLEIMG => 'title.jpg',
	FAVICON => 'wakaba.ico',
	HOME => '../',
	IMAGES_PER_PAGE => 10,
	REPLIES_PER_THREAD => 10,
	IMAGE_REPLIES_PER_THREAD => 0,
	S_ANONAME => 'Anonymous',
	S_ANOTEXT => '',
	S_ANOTITLE => '',
	SILLY_ANONYMOUS => '',
	DEFAULT_STYLE => 'Futaba',

	MAX_KB => 1000,
	MAX_W => 200,
	MAX_H => 200,
	MAX_RES => 20,
	MAX_POSTS => 500,
	MAX_THREADS => 0,
	MAX_AGE => 0,
	MAX_MEGABYTES => 0,
	MAX_FIELD_LENGTH => 100,
	MAX_COMMENT_LENGTH => 8192,
	MAX_LINES_SHOWN => 15,
	MAX_IMAGE_WIDTH => 16384,
	MAX_IMAGE_HEIGHT => 16384,
	MAX_IMAGE_PIXELS => 50000000,

	ENABLE_CAPTCHA => 1,
	CAPTCHA_LIFETIME => 1440,
	CAPTCHA_SCRIPT => 'captcha.pl',
	CAPTCHA_HEIGHT => 18,
	CAPTCHA_SCRIBBLE => 0.2,
	CAPTCHA_SCALING => 0.15,
	CAPTCHA_ROTATION => 0.3,
	CAPTCHA_SPACING => 2.5,

	THUMBNAIL_SMALL => 1,
	THUMBNAIL_QUALITY => 70,
	DELETED_THUMBNAIL => '',
	DELETED_IMAGE => '',
	ALLOW_TEXTONLY => 1,
	ALLOW_IMAGES => 1,
	ALLOW_TEXT_REPLIES => 1,
	ALLOW_IMAGE_REPLIES => 1,
	ALLOW_UNKNOWN => 0,
	MUNGE_UNKNOWN => '.unknown',
	FORBIDDEN_EXTENSIONS => {'php','php3','php4','phtml','shtml','cgi','pl','pm','py','r','exe','dll','scr','pif','asp','cfm','jsp','rb'},
	RENZOKU => 5,
	RENZOKU2 => 10,
	RENZOKU3 => 900,
	NOSAGE_WINDOW => 1200,
	USE_SECURE_ADMIN => 0,
	CHARSET => 'utf-8',
	CONVERT_CHARSETS => 1,
	TRIM_METHOD => 0,
	ARCHIVE_MODE => 0,
	DATE_STYLE => 'futaba',
	DISPLAY_ID => 0,
	EMAIL_ID => 'Heaven',
	TRIPKEY => '!',
	ENABLE_WAKABAMARK => 1,
	APPROX_LINE_LENGTH => 150,
	STUPID_THUMBNAILING => 0,
	ALTERNATE_REDIRECT => 0,
	COOKIE_PATH => 'root',
	STYLE_COOKIE => 'wakabastyle',
	FORCED_ANON => 0,
	USE_XHTML => 1,
	SPAM_TRAP => 1,

	IMG_DIR => 'src/',
	THUMB_DIR => 'thumb/',
	RES_DIR => 'res/',
	ARCHIVE_DIR => 'arch/',
	REDIR_DIR => 'redir/',
	HTML_SELF => 'wakaba.html',
	JS_FILE => 'wakaba3.js',
	CSS_DIR => 'css/',
	PAGE_EXT => '.html'
};

#use constant TITLE => 'Wakaba image board';	# Name of this image board
#use constant SHOWTITLETXT => 1;				# Show TITLE at top (1: yes  0: no)
#use constant SHOWTITLEIMG => 0;				# Show image at top (0: no, 1: single, 2: rotating)
#use constant TITLEIMG => 'title.jpg';			# Title image (point to a script file if rotating)
#use constant FAVICON => 'wakaba.ico';			# Favicon.ico file
#use constant HOME => '../';					# Site home directory (up one level by default
#use constant IMAGES_PER_PAGE => 10;			# Images per page
#use constant REPLIES_PER_THREAD => 10;			# Replies shown
#use constant IMAGE_REPLIES_PER_THREAD => 0;	# Number of image replies per thread to show, set to 0 for no limit.
#use constant S_ANONAME => 'Anonymous';			# Defines what to print if there is no text entered in the name field
#use constant S_ANOTEXT => '';					# Defines what to print if there is no text entered in the comment field
#use constant S_ANOTITLE => '';					# Defines what to print if there is no text entered into subject field
#use constant SILLY_ANONYMOUS => '';			# Make up silly names for anonymous people (0 or '': don't display, any combination of 'day' or 'board': make names change for each day or board, 'static': static names)
#use constant DEFAULT_STYLE => 'Futaba';		# Title of the default style for the board.

# Limitations
#use constant MAX_KB => 1000;					# Maximum upload size in KB
#use constant MAX_W => 200;						# Images exceeding this width will be thumbnailed
#use constant MAX_H => 200;						# Images exceeding this height will be thumbnailed
#use constant MAX_RES => 20;					# Maximum topic bumps
#use constant MAX_POSTS => 500;					# Maximum number of posts (set to 0 to disable)
#use constant MAX_THREADS => 0;					# Maximum number of threads (set to 0 to disable)
#use constant MAX_AGE => 0;						# Maximum age of a thread in hours (set to 0 to disable)
#use constant MAX_MEGABYTES => 0;				# Maximum size to use for all images in megabytes (set to 0 to disable)
#use constant MAX_FIELD_LENGTH => 100;			# Maximum number of characters in subject, name, and email
#use constant MAX_COMMENT_LENGTH => 8192;		# Maximum number of characters in a comment
#use constant MAX_LINES_SHOWN => 15;			# Max lines shown per post (0 = no limit)
#use constant MAX_IMAGE_WIDTH => 16384;			# Maximum width of image before rejecting
#use constant MAX_IMAGE_HEIGHT => 16384;		# Maximum height of image before rejecting
#use constant MAX_IMAGE_PIXELS => 50000000;		# Maximum width*height of image before rejecting

# Captcha
#use constant ENABLE_CAPTCHA => 1;
#use constant SQL_CAPTCHA_TABLE => 'captcha';	# Use a different captcha table for each board, if you have more than one!
#use constant CAPTCHA_LIFETIME => 600;			# Captcha lifetime in seconds
#use constant CAPTCHA_SCRIPT => 'captcha.pl';
#use constant CAPTCHA_HEIGHT => 18;
#use constant CAPTCHA_SCRIBBLE => 0.2;
#use constant CAPTCHA_SCALING => 0.15;
#use constant CAPTCHA_ROTATION => 0.3;
#use constant CAPTCHA_SPACING => 2.5;

# Load Balancing
#use constant ENABLE_LOAD => 0;					# Enable the distribution of image files across multiple hosts (0: no, 1: yes). May not work on a windows host. Do not enable if using STUPID_THUMBNAILING.
#use constant LOAD_SENDER_SCRIPT => './sender.pl';
#use constant LOAD_LOCAL => 120;				# Gigabytes of available bandwidth relative to other hosts (please read documentation)
#use constant LOAD_HOSTS => (['http://somesite/loader.pl', 'password', 100]);
#use constant LOAD_KBRATE => 25;				# minimum send rate that will be accepted without timing out

# Proxy
#use constant ENABLE_PROXY_CHECK => 0;			# Enable proxy checking (0: no, 1:yes). Please read the documentation first!
#use constant PROXY_COMMAND => 'proxycheck -s -d CHANGEME -c chat:CHANGEME ESMTP" -aaaa';	# Only uncomment if you know what you're doing... 
#use constant PROXY_WHITE_AGE => 604800;		# Seconds until confirmed non-proxy entry expires.
#use constant PROXY_BLACK_AGE => 604800;		# Seconds until confirmed proxy entry expires.

# Tweaks
#use constant THUMBNAIL_SMALL => 1;				# Thumbnail small images (1: yes, 0: no)
#use constant THUMBNAIL_QUALITY => 70;			# Thumbnail JPEG quality
#use constant DELETED_THUMBNAIL => '';			# Thumbnail to show for deleted images (leave empty to show text message)
#use constant DELETED_IMAGE => '';				# Image to link for deleted images (only used together with DELETED_THUMBNAIL)
#use constant ALLOW_TEXTONLY => 1;				# Allow textonly posts (1: yes, 0: no)
#use constant ALLOW_IMAGES => 1;				# Allow image posting (1: yes, 0: no)
#use constant ALLOW_TEXT_REPLIES => 1;			# Allow replies (1: yes, 0: no)
#use constant ALLOW_IMAGE_REPLIES => 1;			# Allow replies with images (1: yes, 0: no)
#use constant ALLOW_UNKNOWN => 0;				# Allow unknown filetypes (1: yes, 0: no)
#use constant MUNGE_UNKNOWN => '.unknown';		# Munge unknown file type extensions with this. If you remove this, make sure your web server is locked down properly.
#use constant FORBIDDEN_EXTENSIONS => ('php','php3','php4','phtml','shtml','cgi','pl','pm','py','r','exe','dll','scr','pif','asp','cfm','jsp','vbs'); # file extensions which are forbidden
#use constant RENZOKU => 5;						# Seconds between posts (floodcheck)
#use constant RENZOKU2 => 10;					# Seconds between image posts (floodcheck)
#use constant RENZOKU3 => 900;					# Seconds between identical posts (floodcheck)
#use constant NOSAGE_WINDOW => 1200;			# Seconds that you can post to your own thread without increasing the sage count
#use constant USE_SECURE_ADMIN => 0;			# Use HTTPS for the admin panel.
#use constant CHARSET => 'utf-8';				# Character set to use, typically 'utf-8' or 'shift_jis'. Disable charset handling by setting to ''. Remember to set Apache to use the same character set for .html files! (AddCharset shift_jis html)
#use constant CONVERT_CHARSETS => 1;			# Do character set conversions internally
#use constant TRIM_METHOD => 0;					# Which threads to trim (0: oldest - like futaba 1: least active - furthest back)
#use constant ARCHIVE_MODE => 0;				# Old images and posts are moved into an archive dir instead of deleted (0: no 1: yes). It is HIGHLY RECOMMENDED you use TRIM_METHOD => 1 with this, or you may end up with unreferenced pictures in your archive
#use constant DATE_STYLE => 'futaba';			# Date style ('futaba', '2ch', 'localtime', 'tiny')
#use constant DISPLAY_ID => '';					# How to display user IDs (0 or '': don't display,
												#  'day' and 'board' in any combination: make IDs change for each day or board,
												#  'mask': display masked IP address (similar IPs look similar, but are still encrypted)
												#  'sage': don't display ID when user sages, 'link': don't display ID when the user fills out the link field,
												#  'ip': display user's IP, 'host': display user's host)
#use constant DISPLAY_ID => 0;					# Display user IDs (0: never, 1: if no email, 2:always)
#use constant EMAIL_ID => 'Heaven';				# ID string to use when DISPLAY_ID is 1 and the user uses an email.
#use constant TRIPKEY => '!';					# this character is displayed before tripcodes
#use constant ENABLE_WAKABAMARK => 1;			# Enable WakabaMark formatting. (0: no, 1: yes)
#use constant APPROX_LINE_LENGTH => 150;		# Approximate line length used by reply abbreviation code to guess at the length of a reply.
#use constant STUPID_THUMBNAILING => 0;			# Bypass thumbnailing code and just use HTML to resize the image. STUPID, wastes bandwidth. (1: enable, 0: disable)
#use constant ALTERNATE_REDIRECT => 0;			# Use alternate redirect method. (Javascript/meta-refresh instead of HTTP forwards. Needed to run on certain servers, like IIS.)
#use constant COOKIE_PATH => 'root';			# Path argument for cookies ('root': cookies apply to all boards on the site, 'current': cookies apply only to this board, 'parent': cookies apply to all boards in the parent directory)
#use constant FORCED_ANON => 0;					# Force anonymous posting (0: no, 1: yes)
#use constant USE_XHTML => 1;					# Send pages as application/xhtml+xml to browsers that support this (0:no, 1:yes)
#use constant SPAM_TRAP => 1;					# Enable the spam trap (empty, hidden form fields that spam bots usually fill out) (0:no, 1:yes)

# Internal paths and files - might as well leave this alone.
#use constant IMG_DIR => 'src/';				# Image directory (needs to be writeable by the script)
#use constant THUMB_DIR => 'thumb/';			# Thumbnail directory (needs to be writeable by the script)
#use constant RES_DIR => 'res/';				# Reply cache directory (needs to be writeable by the script)
#use constant ARCHIVE_DIR => 'arch/';			# Root of archive directories (all need to be writeable by the script)
#use constant REDIR_DIR => 'redir/';			# Redir directory, used for redirecting clients when load balancing
#use constant HTML_SELF => 'wakaba.html';		# Name of main html file
#use constant JS_FILE => 'wakaba.js';			# Location of the js file
#use constant PAGE_EXT => '.html';				# Extension used for board pages after first
#use constant ERRORLOG => '';					# Writes out all errors seen by user, mainly useful for debugging
#use constant CONVERT_COMMAND => 'convert';		# location of the ImageMagick convert command (usually just 'convert', but sometime a full path is needed)
##use constant CONVERT_COMMAND => '/usr/X11R6/bin/convert';
#use constant SPAM_FILES => ('spam.txt');		# Spam definition files, as a Perl list.
												# Hints: * Set all boards to use the same file for easy updating.
												#        * Set up two files, one being the official list from
												#          http://wakaba.c3.cx/antispam/spam.txt, and one your own additions.


