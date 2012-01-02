use strict;

BEGIN {
	use constant S_NOADMIN => 'No ADMIN_PASS or NUKE_PASS defined in the configuration';	# Returns error when the config is incomplete
	use constant S_NOSECRET => 'No SECRET defined in the configuration';		# Returns error when the config is incomplete
	use constant S_NOSQL => 'No SQL settings defined in the configuration';		# Returns error when the config is incomplete

	die S_NOADMIN unless(defined &ADMIN_PASS);
	die S_NOADMIN unless(defined &NUKE_PASS);
	die S_NOSECRET unless(defined &SECRET);
	die S_NOSQL unless(defined &SQL_DBI_SOURCE);
	die S_NOSQL unless(defined &SQL_USERNAME);
	die S_NOSQL unless(defined &SQL_PASSWORD);

	eval "use constant SERVER_CONCURRENCY => 10" unless(defined &SERVER_CONCURRENCY);

	eval "use constant SQL_TABLE => 'comments'" unless(defined &SQL_TABLE);
	eval "use constant SQL_COUNTERS_TABLE => 'counters'" unless(defined &SQL_COUNTERS_TABLE);
	eval "use constant SQL_SETTINGS_TABLE => 'settings'" unless(defined &SQL_SETTINGS_TABLE);
	eval "use constant SQL_ADMIN_TABLE => 'admin'" unless(defined &SQL_ADMIN_TABLE);
	eval "use constant SQL_PROXY_TABLE => 'proxy'" unless(defined &SQL_PROXY_TABLE);

	eval "use constant ENABLE_BORAD_AUTOCREATE => 0" unless(defined &ENABLE_BOARD_AUTOCREATE);

	eval "use constant USE_TEMPFILES => 1" unless(defined &USE_TEMPFILES);

	eval "use constant ENABLE_LOAD => 0" unless(defined &ENABLE_LOAD);
	eval "use constant LOAD_SENDER_SCRIPT => 'sender.pl'" unless(defined &LOAD_SENDER_SCRIPT);
	eval "use constant LOAD_LOCAL => 999" unless(defined &LOAD_LOCAL);
	eval "use constant LOAD_HOSTS => ()" unless(defined &LOAD_HOSTS);

	eval "use constant ENABLE_PROXY_CHECK => 0" unless(defined &ENABLE_PROXY_CHECK);
	eval "use constant PROXY_COMMAND => ''" unless(defined &PROXY_COMMAND);
	eval "use constant PROXY_WHITE_AGE => 604800" unless(defined &PROXY_WHITE_AGE);
	eval "use constant PROXY_BLACK_AGE => 604800" unless(defined &PROXY_BLACK_AGE);

	eval "use constant ERRORLOG => ''" unless(defined &ERRORLOG);
	eval "use constant CONVERT_COMMAND => 'convert'" unless(defined &CONVERT_COMMAND);
	unless(defined &SPAM_FILES)
	{
		if(defined &SPAM_FILE) { eval "use constant SPAM_FILES => (SPAM_FILE)" }
		else { eval "use constant SPAM_FILES => ('spam.txt')" }
	}
#	eval "use constant SPAM_FILE => 'spam.txt'" unless(defined &SPAM_FILE);

	eval "use constant FILETYPES => ()" unless(defined &FILETYPES);

	eval "use constant WAKABA_VERSION => '3.0.8'" unless(defined &WAKABA_VERSION);
}

1;
