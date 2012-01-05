#!/usr/bin/perl

use CGI::Carp qw(fatalsToBrowser);

# use strict;

use CGI qw/:standard/;           # load standard CGI routines
use CGI::Fast;
use FCGI::ProcManager qw(pm_manage pm_pre_dispatch 
                         pm_post_dispatch);
use DBI;
use JSON;

#
# Import settings
#

use lib '.';
BEGIN { require "config.pl"; }
BEGIN { require "config_defaults.pl"; }
BEGIN { require "default_settings.pl"; }
BEGIN { require "strings_en.pl"; }	# edit this line to change the language
BEGIN { require "futaba_style.pl"; }	# edit this line to change the board style
BEGIN { require "captcha.pl"; }
BEGIN { require "wakautils.pl"; }

pm_manage(n_processes => SERVER_CONCURRENCY);

#
# Optional modules
#

my ($has_encode);

if($$cfg{CONVERT_CHARSETS})
{
	eval 'use Encode qw(decode encode)';
	$has_encode=1 unless($@);
}



#
# Global init
#

my $boardSection = ''; 
our $cfg = {};

my $protocol_re=qr/(?:http|https|ftp|mailto|nntp)/;

my $dbh=DBI->connect(SQL_DBI_SOURCE,SQL_USERNAME,SQL_PASSWORD,
	{AutoCommit=>1, RaiseError=>1}) or make_error(S_SQLCONF);

return 1 if(caller); # stop here if we're being called externally
# check for admin table
init_admin_database() if(!table_exists(SQL_ADMIN_TABLE));

# check for proxy table
init_proxy_database() if(!table_exists(SQL_PROXY_TABLE));

if(!table_exists(SQL_SETTINGS_TABLE)) # check for settings table
{
	init_settings_database();
}

if(!table_exists(SQL_TABLE)) # check for comments table
{
	init_database();
	build_cache($boardSection);
	make_http_forward($$cfg{HTML_SELF},$$cfg{ALTERNATE_REDIRECT});
}

while (my $query=new CGI::Fast) {
	pm_pre_dispatch();

	my $task=($query->param("task") or $query->param("action"));

	$boardSection = ($query->param("section") or 'default');
	eval { $cfg = fetch_config($dbh,$boardSection); };
	if ($@) 
	{
		print $@;
		if (ENABLE_BOARD_AUTOCREATE 
			and $boardSection =~ /^${\(BOARD_AUTOCREATE_PREFIX)}/)
		{
			init_section($boardSection);
			$cfg = fetch_config($dbh,$boardSection);	
		} 
		else
		{
			make_http_error('404 Section not found', '');
		}
		
	}

  	if(!$task)
	{
		build_cache($boardSection) unless -e $$cfg{HTML_SELF};
		make_http_forward($$cfg{HTML_SELF},$$cfg{ALTERNATE_REDIRECT});
	}
	elsif($task eq "post")
	{
		my $parent=$query->param("parent");
		my $name=$query->param("field1");
		my $email=$query->param("field2");
		my $subject=$query->param("field3");
		my $comment=$query->param("field4");
		my $file=$query->param("file");
		my $password=$query->param("password");
		my $nofile=$query->param("nofile");
		my $captcha=$query->param("captcha");
		my $admin=$query->param("admin");
		my $no_captcha=$query->param("no_captcha");
		my $no_format=$query->param("no_format");
		my $postfix=$query->param("postfix");

		post_stuff($boardSection,$parent,$name,$email,$subject,$comment,$file,$file,$password,$nofile,$captcha,$admin,$no_captcha,$no_format,$postfix);
	}
	elsif($task eq "delete")
	{
		my $password=$query->param("password");
		my $fileonly=$query->param("fileonly");
		my $archive=$query->param("archive");
		my $admin=$query->param("admin");
		my @posts=$query->param("delete");

		delete_stuff($boardSection,$password,$fileonly,$archive,$admin,@posts);
	}
	elsif($task eq "admin")
	{
		my $password=$query->param("berra"); # lol obfuscation
		my $nexttask=$query->param("nexttask");
		my $savelogin=$query->param("savelogin");
		my $admincookie=$query->cookie("wakaadmin");

		do_login($password,$nexttask,$savelogin,$admincookie);
	}
	elsif($task eq "logout")
	{
		do_logout();
	}
	elsif($task eq "mpanel")
	{
		my $admin=$query->param("admin");
		make_admin_post_panel($admin);
	}
	elsif($task eq "deleteall")
	{
		my $admin=$query->param("admin");
		my $ip=$query->param("ip");
		my $mask=$query->param("mask");
		delete_all($boardSection,$admin,parse_range($ip,$mask));
	}
	elsif($task eq "bans")
	{
		my $admin=$query->param("admin");
		make_admin_ban_panel($admin);
	}
	elsif($task eq "addip")
	{
		my $admin=$query->param("admin");
		my $type=$query->param("type");
		my $comment=$query->param("comment");
		my $ip=$query->param("ip");
		my $mask=$query->param("mask");
		add_admin_entry($admin,$type,$comment,parse_range($ip,$mask),'');
	}
	elsif($task eq "addstring")
	{
		my $admin=$query->param("admin");
		my $type=$query->param("type");
		my $string=$query->param("string");
		my $comment=$query->param("comment");
		add_admin_entry($admin,$type,$comment,0,0,$string);
	}
	elsif($task eq "removeban")
	{
		my $admin=$query->param("admin");
		my $num=$query->param("num");
		remove_admin_entry($admin,$num);
	}
	elsif($task eq "proxy")
	{
		my $admin=$query->param("admin");
		make_admin_proxy_panel($admin);
	}
	elsif($task eq "addproxy")
	{
		my $admin=$query->param("admin");
		my $type=$query->param("type");
		my $ip=$query->param("ip");
		my $timestamp=$query->param("timestamp");
		my $date=make_date(time(),$$cfg{DATE_STYLE});
		add_proxy_entry($admin,$type,$ip,$timestamp,$date);
	}
	elsif($task eq "removeproxy")
	{
		my $admin=$query->param("admin");
		my $num=$query->param("num");
		remove_proxy_entry($admin,$num);
	}
	elsif($task eq "spam")
	{
		my ($admin);
		$admin=$query->param("admin");
		make_admin_spam_panel($admin);
	}
	elsif($task eq "updatespam")
	{
		my $admin=$query->param("admin");
		my $spam=$query->param("spam");
		update_spam_file($admin,$spam);
	}
	elsif($task eq "sqldump")
	{
		my $admin=$query->param("admin");
		make_sql_dump($admin);
	}
	elsif($task eq "sql")
	{
		my $admin=$query->param("admin");
		my $nuke=$query->param("nuke");
		my $sql=$query->param("sql");
		make_sql_interface($admin,$nuke,$sql);
	}
	elsif($task eq "mpost")
	{
		my $admin=$query->param("admin");
		make_admin_post($admin);
	}
	elsif($task eq "rebuild")
	{
		my $admin=$query->param("admin");
		do_rebuild_cache($boardSection,$admin);
	}
	elsif($task eq "nuke")
	{
		my $admin=$query->param("admin");
		do_nuke_database($admin);
	}
	elsif($task eq "sectioncfg")
	{
		my $admin=$query->param("admin");
		make_admin_section_panel($admin, $boardSection);
	}
	elsif($task eq "updatesectioncfg")
	{
		my $admin=$query->param("admin");
		my $sectionConfig=$query->param("sectionConfig");
		do_update_sectioncfg($admin,$boardSection,$sectionConfig);
	}
	else
	{
		make_error(S_TASK404);
	}

	pm_post_dispatch();
}


$dbh->disconnect();

#
# Cache page creation
#

sub build_cache($)
{
	my ($section) = @_;
	my ($sth,$row,@thread);
	my $page=0;

	# grab all posts, in thread order (ugh, ugly kludge)
	$sth=$dbh->prepare(
		"SELECT * FROM ".SQL_TABLE." WHERE section=? ".
		"ORDER BY lasthit DESC,CASE parent WHEN 0 THEN num ELSE parent END ASC,num ASC"
	) or make_error(S_SQLFAIL);
	$sth->execute($section) or make_error(S_SQLFAIL);

	$row=get_decoded_hashref($sth);

	if(!$row) # no posts on the board!
	{
		build_cache_page(0,1); # make an empty page 0
	}
	else
	{
		my @threads;
		my @thread=($row);

		while($row=get_decoded_hashref($sth))
		{
			if(!$$row{parent})
			{
				push @threads,{posts=>[@thread]};
				@thread=($row); # start new thread
			}
			else
			{
				push @thread,$row;
			}
		}
		push @threads,{posts=>[@thread]};

		my $total=get_page_count(scalar @threads);
		my @pagethreads;
		while(@pagethreads=splice @threads,0,$$cfg{IMAGES_PER_PAGE})
		{
			build_cache_page($page,$total,@pagethreads);
			$page++;
		}
	}

	# check for and remove old pages
	while(-e $page.$$cfg{PAGE_EXT})
	{
		unlink $page.$$cfg{PAGE_EXT};
		$page++;
	}
}

sub build_cache_page($$@)
{
	my ($page,$total,@threads)=@_;
	my ($filename,$tmpname);

	if($page==0) { $filename=$$cfg{HTML_SELF}; }
	else { $filename=$page.$$cfg{PAGE_EXT}; }

	# do abbrevations and such
	foreach my $thread (@threads)
	{
		# split off the parent post, and count the replies and images
		my ($parent,@replies)=@{$$thread{posts}};
		my $replies=@replies;
		my $images=grep { $$_{image} } @replies;
		my $curr_replies=$replies;
		my $curr_images=$images;
		my $max_replies=$$cfg{REPLIES_PER_THREAD};
		my $max_images=($$cfg{IMAGE_REPLIES_PER_THREAD} or $images);

		# drop replies until we have few enough replies and images
		while($curr_replies>$max_replies or $curr_images>$max_images)
		{
			my $post=shift @replies;
			$curr_images-- if($$post{image});
			$curr_replies--;
		}

		# write the shortened list of replies back
		$$thread{posts}=[$parent,@replies];
		$$thread{omit}=$replies-$curr_replies;
		$$thread{omitimages}=$images-$curr_images;

		# abbreviate the remaining posts
		foreach my $post (@{$$thread{posts}})
		{
			my $abbreviation=abbreviate_html($$post{comment},$$cfg{MAX_LINES_SHOWN},$$cfg{APPROX_LINE_LENGTH});
			if($abbreviation)
			{
				$$post{comment}=$abbreviation;
				$$post{abbrev}=1;
			}
		}
	}

	# make the list of pages
	my @pages=map +{ page=>$_ },(0..$total-1);
	foreach my $p (@pages)
	{
		if($$p{page}==0) { $$p{filename}=expand_filename($$cfg{HTML_SELF}) } # first page
		else { $$p{filename}=expand_filename($$p{page}.$$cfg{PAGE_EXT}) }
		if($$p{page}==$page) { $$p{current}=1 } # current page, no link
	}

	my ($prevpage,$nextpage);
	$prevpage=$pages[$page-1]{filename} if($page!=0);
	$nextpage=$pages[$page+1]{filename} if($page!=$total-1);

	print_page($filename,PAGE_TEMPLATE->(
		cfg=>$cfg,
		stylesheets=>get_stylesheets($$cfg{DEFAULT_STYLE}, $$cfg{CSS_DIR}),
		postform=>($$cfg{ALLOW_TEXTONLY} or $$cfg{ALLOW_IMAGES}),
		image_inp=>$$cfg{ALLOW_IMAGES},
		textonly_inp=>($$cfg{ALLOW_IMAGES} and $$cfg{ALLOW_TEXTONLY}),
		prevpage=>$prevpage,
		nextpage=>$nextpage,
		pages=>\@pages,
		threads=>\@threads
	));
}

sub build_thread_cache($$)
{
	my ($section,$thread)=@_;
	my ($sth,$row,@thread);
	my ($filename,$tmpname);

	$sth=$dbh->prepare("SELECT * FROM ".SQL_TABLE." WHERE num=? AND section=? OR parent=? ORDER BY num ASC;") or make_error(S_SQLFAIL);
	$sth->execute($thread,$section,$thread) or make_error(S_SQLFAIL);

	while($row=get_decoded_hashref($sth)) { push(@thread,$row); }

	make_error(S_NOTHREADERR) if($thread[0]{parent});

	$filename=$$cfg{RES_DIR}.$thread.$$cfg{PAGE_EXT};

	print_page($filename,PAGE_TEMPLATE->(
		thread=>$thread,
		postform=>($$cfg{ALLOW_TEXT_REPLIES} or $$cfg{ALLOW_IMAGE_REPLIES}),
		image_inp=>$$cfg{ALLOW_IMAGE_REPLIES},
		textonly_inp=>0,
		dummy=>$thread[$#thread]{num},
		threads=>[{posts=>\@thread}])
	);
}

sub print_page($$)
{
	my ($filename,$contents)=@_;

	$contents=encode_string($contents);
#		$PerlIO::encoding::fallback=0x0200 if($has_encode);
#		binmode PAGE,':encoding('.$$cfg{CHARSET}.')' if($has_encode);

	if(USE_TEMPFILES)
	{
		my $tmpname=$$cfg{RES_DIR}.'tmp'.int(rand(1000000000));

		open (PAGE,">$tmpname") or make_error(S_NOTWRITE);
		print PAGE $contents;
		close PAGE;

		rename $tmpname,$filename;
	}
	else
	{
		open (PAGE,">$filename") or make_error(S_NOTWRITE);
		print PAGE $contents;
		close PAGE;
	}
}

sub build_thread_cache_all($)
{
	my ($section) = @_;
	my ($sth,$row,@thread);

	$sth=$dbh->prepare("SELECT num FROM ".SQL_TABLE." WHERE parent=0;") or make_error(S_SQLFAIL);
	$sth->execute() or make_error(S_SQLFAIL);

	while($row=$sth->fetchrow_arrayref())
	{
		build_thread_cache($section,$$row[0]);
	}
}



#
# Posting
#

sub post_stuff($$$$$$$$$$$$$$$)
{
	my ($section,$parent,$name,$email,$subject,$comment,$file,$uploadname,$password,$nofile,$captcha,$admin,$no_captcha,$no_format,$postfix)=@_;

	# get a timestamp for future use
	my $time=time();

	# check that the request came in as a POST, or from the command line
	make_error(S_UNJUST) if($ENV{REQUEST_METHOD} and $ENV{REQUEST_METHOD} ne "POST");

	if($admin) # check admin password - allow both encrypted and non-encrypted
	{
		check_password($admin,ADMIN_PASS);
	}
	else
	{
		# forbid admin-only features
		make_error(S_WRONGPASS) if($no_captcha or $no_format or $postfix);

		# check what kind of posting is allowed
		if($parent)
		{
			make_error(S_NOTALLOWED) if($file and !$$cfg{ALLOW_IMAGE_REPLIES});
			make_error(S_NOTALLOWED) if(!$file and !$$cfg{ALLOW_TEXT_REPLIES});
		}
		else
		{
			make_error(S_NOTALLOWED) if($file and !$$cfg{ALLOW_IMAGES});
			make_error(S_NOTALLOWED) if(!$file and !$$cfg{ALLOW_TEXTONLY});
		}
	}

	# check for weird characters
	make_error(S_UNUSUAL) if($parent=~/[^0-9]/);
	make_error(S_UNUSUAL) if(length($parent)>10);
	make_error(S_UNUSUAL) if($name=~/[\n\r]/);
	make_error(S_UNUSUAL) if($email=~/[\n\r]/);
	make_error(S_UNUSUAL) if($subject=~/[\n\r]/);

	# check for excessive amounts of text
	make_error(S_TOOLONG) if(length($name)>$$cfg{MAX_FIELD_LENGTH});
	make_error(S_TOOLONG) if(length($email)>$$cfg{MAX_FIELD_LENGTH});
	make_error(S_TOOLONG) if(length($subject)>$$cfg{MAX_FIELD_LENGTH});
	make_error(S_TOOLONG) if(length($comment)>$$cfg{MAX_COMMENT_LENGTH});

	# check to make sure the user selected a file, or clicked the checkbox
	make_error(S_NOPIC) if(!$parent and !$file and !$nofile and !$admin);

	# check for empty reply or empty text-only post
	make_error(S_NOTEXT) if($comment=~/^\s*$/ and !$file);

	# get file size, and check for limitations.
	my $size=get_file_size($file) if($file);

	# find IP
	my $ip=$ENV{REMOTE_ADDR};

	#$host = gethostbyaddr($ip);
	my $numip=dot_to_dec($ip);

	# set up cookies
	my $c_name=$name;
	my $c_email=$email;
	my $c_password=$password;

	# check if IP is whitelisted
	my $whitelisted=is_whitelisted($numip);

	# process the tripcode - maybe the string should be decoded later
	my $trip;
	($name,$trip)=process_tripcode($name,$$cfg{TRIPKEY},SECRET,$$cfg{CHARSET});

	# check for bans
	ban_check($numip,$c_name,$subject,$comment) unless $whitelisted;

	# spam check
	spam_engine(
		query=>$query,
		trap_fields=>$$cfg{SPAM_TRAP}?["name","link"]:[],
		spam_files=>[SPAM_FILES],
		charset=>$$cfg{CHARSET},
		included_fields=>["field1","field2","field3","field4"],
	) unless $whitelisted;

	# check captcha
	check_captcha($dbh,$boardSection,$captcha,$ip,$parent) if($$cfg{ENABLE_CAPTCHA} and !$no_captcha and !is_trusted($trip));

	# proxy check
	proxy_check($ip) if (!$whitelisted and ENABLE_PROXY_CHECK);

	# check if thread exists, and get lasthit value
	my ($parent_res,$lasthit);
	if($parent)
	{
		$parent_res=get_parent_post($parent) or make_error(S_NOTHREADERR);
		$lasthit=$$parent_res{lasthit};
	}
	else
	{
		$lasthit=$time;
	}


	# kill the name if anonymous posting is being enforced
	if($$cfg{FORCED_ANON})
	{
		$name='';
		$trip='';
		if($email=~/sage/i) { $email='sage'; }
		else { $email=''; }
	}

	# clean up the inputs
	$email=clean_string(decode_string($email,$$cfg{CHARSET}));
	$subject=clean_string(decode_string($subject,$$cfg{CHARSET}));

	# fix up the email/link
	$email="mailto:$email" if $email and $email!~/^$protocol_re:/;

	# format comment
	$comment=format_comment(clean_string(decode_string($comment,$$cfg{CHARSET}))) unless $no_format;
	$comment.=$postfix;

	# insert default values for empty fields
	$parent=0 unless $parent;
	$name=make_anonymous($ip,$time) unless $name or $trip;
	$subject=$$cfg{S_ANOTITLE} unless $subject;
	$comment=$$cfg{S_ANOTEXT} unless $comment;

	# flood protection - must happen after inputs have been cleaned up
	flood_check($numip,$time,$comment,$file);

	# Manager and deletion stuff - duuuuuh?

	# generate date
	my $date=make_date($time,$$cfg{DATE_STYLE});

	# generate ID code if enabled
	$date.=' ID:'.make_id_code($ip,$time,$email) if($$cfg{DISPLAY_ID});

	# copy file, do checksums, make thumbnail, etc
	my ($filename,$md5,$width,$height,$thumbnail,$tn_width,$tn_height)=process_file($file,$uploadname,$time) if($file);

	# finally, write to the database
	my $num = 0;
	eval {
		$dbh->begin_work();

		my $sth=$dbh->prepare("UPDATE ".SQL_COUNTERS_TABLE." SET counter = counter + 1 WHERE section = ?;");
		$sth->execute($section);

		$sth=$dbh->prepare("SELECT counter FROM ".SQL_COUNTERS_TABLE." WHERE section = ?;");
		$sth->execute($section);
		$num=($sth->fetchrow_array())[0];

		$sth=$dbh->prepare("INSERT INTO ".SQL_TABLE." VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
		$sth->execute(
			$parent,$time,$lasthit,$numip,$date,$name,$trip,$email,$subject,$password,$comment,
			$filename,$size,$md5,$width,$height,$thumbnail,$tn_width,$tn_height,$section,$num
		);

		$dbh->commit();
	};
	if ($@) {
		eval { $dbh->rollback(); };
		make_error(S_SQLFAIL);
	}

	if($parent) # bumping
	{
		# check for sage, or too many replies
		unless($email=~/sage/i or sage_count($parent_res)>$$cfg{MAX_RES})
		{
			$sth=$dbh->prepare("UPDATE ".SQL_TABLE." SET lasthit=$time WHERE (num=? OR parent=?) AND section=?;") or make_error(S_SQLFAIL);
			$sth->execute($parent,$parent,$section) or make_error(S_SQLFAIL);
		}
	}

	# remove old threads from the database
	trim_database($section);

	# update the cached HTML pages
	build_cache($section);

	# update the individual thread cache
	build_thread_cache($section,($parent or $num)) if ($parent or $num);

	# set the name, email and password cookies
	make_cookies(name=>$c_name,email=>$c_email,password=>$c_password,
	-charset=>$$cfg{CHARSET},-autopath=>$$cfg{COOKIE_PATH}); # yum!

	# forward back to the main page
	make_http_forward($$cfg{HTML_SELF},$$cfg{ALTERNATE_REDIRECT});
}

sub is_whitelisted($)
{
	my ($numip)=@_;
	my ($sth);

	$sth=$dbh->prepare("SELECT count(*) FROM ".SQL_ADMIN_TABLE."
WHERE type='whitelist' AND ? & ival2 = ival1 & ival2;") or make_error(S_SQLFAIL);
	$sth->execute($numip) or make_error(S_SQLFAIL);

	return 1 if(($sth->fetchrow_array())[0]);

	return 0;
}

sub is_trusted($)
{
	my ($trip)=@_;
	my ($sth);
        $sth=$dbh->prepare("SELECT count(*) FROM ".SQL_ADMIN_TABLE." WHERE type='trust' AND sval1 = ?;") or make_error(S_SQLFAIL);
        $sth->execute($trip) or make_error(S_SQLFAIL);

        return 1 if(($sth->fetchrow_array())[0]);

	return 0;
}

sub ban_check($$$$)
{
	my ($numip,$name,$subject,$comment)=@_;
	my ($sth);

	$sth=$dbh->prepare("SELECT count(*) FROM ".SQL_ADMIN_TABLE." WHERE type='ipban' AND ? & ival2 = ival1 & ival2;") or make_error(S_SQLFAIL);
	$sth->execute($numip) or make_error(S_SQLFAIL);

	make_error(S_BADHOST) if(($sth->fetchrow_array())[0]);

# fucking mysql...
#	$sth=$dbh->prepare("SELECT count(*) FROM ".SQL_ADMIN_TABLE." WHERE type='wordban' AND ? LIKE '%' || sval1 || '%';") or make_error(S_SQLFAIL);
#	$sth->execute($comment) or make_error(S_SQLFAIL);
#
#	make_error(S_STRREF) if(($sth->fetchrow_array())[0]);

	$sth=$dbh->prepare("SELECT sval1 FROM ".SQL_ADMIN_TABLE." WHERE type='wordban';") or make_error(S_SQLFAIL);
	$sth->execute() or make_error(S_SQLFAIL);

	my $row;
	while($row=$sth->fetchrow_arrayref())
	{
		my $regexp=quotemeta $$row[0];
		make_error(S_STRREF) if($comment=~/$regexp/);
		make_error(S_STRREF) if($name=~/$regexp/);
		make_error(S_STRREF) if($subject=~/$regexp/);
	}

	# etc etc etc

	return(0);
}

sub flood_check($$$$)
{
	my ($ip,$time,$comment,$file)=@_;
	my ($sth,$maxtime);

	if($file)
	{
		# check for to quick file posts
		$maxtime=$time-($$cfg{RENZOKU2});
		$sth=$dbh->prepare("SELECT count(*) FROM ".SQL_TABLE." WHERE ip=? AND timestamp>$maxtime;") or make_error(S_SQLFAIL);
		$sth->execute($ip) or make_error(S_SQLFAIL);
		make_error(S_RENZOKU2) if(($sth->fetchrow_array())[0]);
	}
	else
	{
		# check for too quick replies or text-only posts
		$maxtime=$time-($$cfg{RENZOKU});
		$sth=$dbh->prepare("SELECT count(*) FROM ".SQL_TABLE." WHERE ip=? AND timestamp>$maxtime;") or make_error(S_SQLFAIL);
		$sth->execute($ip) or make_error(S_SQLFAIL);
		make_error(S_RENZOKU) if(($sth->fetchrow_array())[0]);

		# check for repeated messages
		$maxtime=$time-($$cfg{RENZOKU3});
		$sth=$dbh->prepare("SELECT count(*) FROM ".SQL_TABLE." WHERE ip=? AND comment=? AND timestamp>$maxtime;") or make_error(S_SQLFAIL);
		$sth->execute($ip,$comment) or make_error(S_SQLFAIL);
		make_error(S_RENZOKU3) if(($sth->fetchrow_array())[0]);
	}
}

sub proxy_check($)
{
	my ($ip)=@_;
	my ($sth);

	proxy_clean();

	# check if IP is from a known banned proxy
	$sth=$dbh->prepare("SELECT count(*) FROM ".SQL_PROXY_TABLE." WHERE type='black' AND ip = ?;") or make_error(S_SQLFAIL);
	$sth->execute($ip) or make_error(S_SQLFAIL);

	make_error(S_BADHOSTPROXY) if(($sth->fetchrow_array())[0]);

	# check if IP is from a known non-proxy
	$sth=$dbh->prepare("SELECT count(*) FROM ".SQL_PROXY_TABLE." WHERE type='white' AND ip = ?;") or make_error(S_SQLFAIL);
	$sth->execute($ip) or make_error(S_SQLFAIL);

        my $timestamp=time();
        my $date=make_date($timestamp,$$cfg{DATE_STYLE});

	if(($sth->fetchrow_array())[0])
	{	# known good IP, refresh entry
		$sth=$dbh->prepare("UPDATE ".SQL_PROXY_TABLE." SET timestamp=?, date=? WHERE ip=?;") or make_error(S_SQLFAIL);
		$sth->execute($timestamp,$date,$ip) or make_error(S_SQLFAIL);
	}
	else
	{	# unknown IP, check for proxy
		my $command = PROXY_COMMAND . " " . $ip;
		$sth=$dbh->prepare("INSERT INTO ".SQL_PROXY_TABLE." VALUES(null,?,?,?,?);") or make_error(S_SQLFAIL);

		if(`$command`)
		{
			$sth->execute('black',$ip,$timestamp,$date) or make_error(S_SQLFAIL);
			make_error(S_PROXY);
		} 
		else
		{
			$sth->execute('white',$ip,$timestamp,$date) or make_error(S_SQLFAIL);
		}
	}
}

sub add_proxy_entry($$$$$)
{
	my ($admin,$type,$ip,$timestamp,$date)=@_;
	my ($sth);

	check_password($admin,ADMIN_PASS);

	# Verifies IP range is sane. The price for a human-readable db...
	unless ($ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/ && $1 <= 255 && $2 <= 255 && $3 <= 255 && $4 <= 255) {
		make_error(S_BADIP);
	}
	if ($type = 'white') { 
		$timestamp = $timestamp - PROXY_WHITE_AGE + time(); 
	}
	else
	{
		$timestamp = $timestamp - PROXY_BLACK_AGE + time(); 
	}	

	# This is to ensure user doesn't put multiple entries for the same IP
	$sth=$dbh->prepare("DELETE FROM ".SQL_PROXY_TABLE." WHERE ip=?;") or make_error(S_SQLFAIL);
	$sth->execute($ip) or make_error(S_SQLFAIL);

	# Add requested entry
	$sth=$dbh->prepare("INSERT INTO ".SQL_PROXY_TABLE." VALUES(null,?,?,?,?);") or make_error(S_SQLFAIL);
	$sth->execute($type,$ip,$timestamp,$date) or make_error(S_SQLFAIL);

        make_http_forward(get_script_name()."?admin=$admin&task=proxy",$$cfg{ALTERNATE_REDIRECT});
}

sub proxy_clean()
{
	my ($sth,$timestamp);

	if(PROXY_BLACK_AGE == PROXY_WHITE_AGE)
	{
		$timestamp = time() - PROXY_BLACK_AGE;
		$sth=$dbh->prepare("DELETE FROM ".SQL_PROXY_TABLE." WHERE timestamp<?;") or make_error(S_SQLFAIL);
		$sth->execute($timestamp) or make_error(S_SQLFAIL);
	} 
	else
	{
		$timestamp = time() - PROXY_BLACK_AGE;
		$sth=$dbh->prepare("DELETE FROM ".SQL_PROXY_TABLE." WHERE type='black' AND timestamp<?;") or make_error(S_SQLFAIL);
		$sth->execute($timestamp) or make_error(S_SQLFAIL);

		$timestamp = time() - PROXY_WHITE_AGE;
		$sth=$dbh->prepare("DELETE FROM ".SQL_PROXY_TABLE." WHERE type='white' AND timestamp<?;") or make_error(S_SQLFAIL);
		$sth->execute($timestamp) or make_error(S_SQLFAIL);
	}
}

sub remove_proxy_entry($$)
{
	my ($admin,$num)=@_;
	my ($sth);

	check_password($admin,ADMIN_PASS);

	$sth=$dbh->prepare("DELETE FROM ".SQL_PROXY_TABLE." WHERE num=?;") or make_error(S_SQLFAIL);
	$sth->execute($num) or make_error(S_SQLFAIL);

	make_http_forward(get_script_name()."?admin=$admin&task=proxy",$$cfg{ALTERNATE_REDIRECT});
}

sub format_comment($)
{
	my ($comment)=@_;

	# hide >>1 references from the quoting code
	$comment=~s/&gt;&gt;([0-9\-]+)/&gtgt;$1/g;

	my $handler=sub # fix up >>1 references
	{
		my $line=shift;

		$line=~s!&gtgt;([0-9]+)!
			my $res=get_post($1);
			if($res) { '<a href="'.get_reply_link($$res{num},$$res{parent}).'" onclick="highlight('.$1.')">&gt;&gt;'.$1.'</a>' }
			else { "&gt;&gt;$1"; }
		!ge;

		return $line;
	};

	if($$cfg{ENABLE_WAKABAMARK}) { $comment=do_wakabamark($comment,$handler) }
	else { $comment="<p>".simple_format($comment,$handler)."</p>" }

	# fix <blockquote> styles for old stylesheets
	$comment=~s/<blockquote>/<blockquote class="unkfunc">/g;

	# restore >>1 references hidden in code blocks
	$comment=~s/&gtgt;/&gt;&gt;/g;

	return $comment;
}

sub simple_format($@)
{
	my ($comment,$handler)=@_;
	return join "<br />",map
	{
		my $line=$_;

		# make URLs into links
		$line=~s{(https?://[^\s<>"]*?)((?:\s|<|>|"|\.|\)|\]|!|\?|,|&#44;|&quot;)*(?:[\s<>"]|$))}{\<a href="$1"\>$1\</a\>$2}sgi;

		# colour quoted sections if working in old-style mode.
		$line=~s!^(&gt;.*)$!\<span class="unkfunc"\>$1\</span\>!g unless($$cfg{ENABLE_WAKABAMARK});

		$line=$handler->($line) if($handler);

		$line;
	} split /\n/,$comment;
}

sub encode_string($)
{
	my ($str)=@_;

	return $str unless($has_encode);
	return encode($$cfg{CHARSET},$str,0x0400);
}

sub make_anonymous($$)
{
	my ($ip,$time)=@_;

	return $$cfg{S_ANONAME} unless($$cfg{SILLY_ANONYMOUS});

	my $string=$ip;
	$string.=",".int($time/86400) if($$cfg{SILLY_ANONYMOUS}=~/day/i);
	$string.=",".$ENV{SCRIPT_NAME} if($$cfg{SILLY_ANONYMOUS}=~/board/i);

	srand unpack "N",hide_data($string,4,"silly",SECRET);

	return cfg_expand("%G% %W%",
		W => ["%B%%V%%M%%I%%V%%F%","%B%%V%%M%%E%","%O%%E%","%B%%V%%M%%I%%V%%F%","%B%%V%%M%%E%","%O%%E%","%B%%V%%M%%I%%V%%F%","%B%%V%%M%%E%"],
		B => ["B","B","C","D","D","F","F","G","G","H","H","M","N","P","P","S","S","W","Ch","Br","Cr","Dr","Bl","Cl","S"],
		I => ["b","d","f","h","k","l","m","n","p","s","t","w","ch","st"],
		V => ["a","e","i","o","u"],
		M => ["ving","zzle","ndle","ddle","ller","rring","tting","nning","ssle","mmer","bber","bble","nger","nner","sh","ffing","nder","pper","mmle","lly","bling","nkin","dge","ckle","ggle","mble","ckle","rry"],
		F => ["t","ck","tch","d","g","n","t","t","ck","tch","dge","re","rk","dge","re","ne","dging"],
		O => ["Small","Snod","Bard","Billing","Black","Shake","Tilling","Good","Worthing","Blythe","Green","Duck","Pitt","Grand","Brook","Blather","Bun","Buzz","Clay","Fan","Dart","Grim","Honey","Light","Murd","Nickle","Pick","Pock","Trot","Toot","Turvey"],
		E => ["shaw","man","stone","son","ham","gold","banks","foot","worth","way","hall","dock","ford","well","bury","stock","field","lock","dale","water","hood","ridge","ville","spear","forth","will"],
		G => ["Albert","Alice","Angus","Archie","Augustus","Barnaby","Basil","Beatrice","Betsy","Caroline","Cedric","Charles","Charlotte","Clara","Cornelius","Cyril","David","Doris","Ebenezer","Edward","Edwin","Eliza","Emma","Ernest","Esther","Eugene","Fanny","Frederick","George","Graham","Hamilton","Hannah","Hedda","Henry","Hugh","Ian","Isabella","Jack","James","Jarvis","Jenny","John","Lillian","Lydia","Martha","Martin","Matilda","Molly","Nathaniel","Nell","Nicholas","Nigel","Oliver","Phineas","Phoebe","Phyllis","Polly","Priscilla","Rebecca","Reuben","Samuel","Sidney","Simon","Sophie","Thomas","Walter","Wesley","William"],
	);
}

sub make_id_code($$$)
{
	my ($ip,$time,$link)=@_;

	return $$cfg{EMAIL_ID} if($link and $$cfg{DISPLAY_ID}=~/link/i);
	return $$cfg{EMAIL_ID} if($link=~/sage/i and $$cfg{DISPLAY_ID}=~/sage/i);

	return resolve_host($ENV{REMOTE_ADDR}) if($$cfg{DISPLAY_ID}=~/host/i);
	return $ENV{REMOTE_ADDR} if($$cfg{DISPLAY_ID}=~/ip/i);

	my $string="";
	$string.=",".int($time/86400) if($$cfg{DISPLAY_ID}=~/day/i);
	$string.=",".$ENV{SCRIPT_NAME} if($$cfg{DISPLAY_ID}=~/board/i);

	return mask_ip($ENV{REMOTE_ADDR},make_key("mask",SECRET,32).$string) if($$cfg{DISPLAY_ID}=~/mask/i);

	return hide_data($ip.$string,6,"id",SECRET,1);
}

sub get_post($)
{
	my ($thread)=@_;
	my ($sth);

	$sth=$dbh->prepare("SELECT * FROM ".SQL_TABLE." WHERE num=?;") or make_error(S_SQLFAIL);
	$sth->execute($thread) or make_error(S_SQLFAIL);

	return $sth->fetchrow_hashref();
}

sub get_parent_post($)
{
	my ($thread)=@_;
	my ($sth);

	$sth=$dbh->prepare("SELECT * FROM ".SQL_TABLE." WHERE num=? AND parent=0;") or make_error(S_SQLFAIL);
	$sth->execute($thread) or make_error(S_SQLFAIL);

	return $sth->fetchrow_hashref();
}

sub sage_count($)
{
	my ($parent)=@_;
	my ($sth);

	$sth=$dbh->prepare("SELECT count(*) FROM ".SQL_TABLE." WHERE parent=? AND NOT ( timestamp<? AND ip=? );") or make_error(S_SQLFAIL);
	$sth->execute($$parent{num},$$parent{timestamp}+($$cfg{NOSAGE_WINDOW}),$$parent{ip}) or make_error(S_SQLFAIL);

	return ($sth->fetchrow_array())[0];
}

sub get_file_size($)
{
	my ($file)=@_;
	my (@filestats,$size);

	@filestats=stat $file;
	$size=$filestats[7];

	make_error(S_TOOBIG) if($size>$$cfg{MAX_KB}*1024);
	make_error(S_TOOBIGORNONE) if($size==0); # check for small files, too?

	return($size);
}

sub process_file($$$)
{
	my ($file,$uploadname,$time)=@_;
	my %filetypes=FILETYPES;

	# make sure to read file in binary mode on platforms that care about such things
	binmode $file;

	# analyze file and check that it's in a supported format
	my ($ext,$width,$height)=analyze_image($file,$uploadname);

	my $known=($width or $filetypes{$ext});

	make_error(S_BADFORMAT) unless($$cfg{ALLOW_UNKNOWN} or $known);
	make_error(S_BADFORMAT) if(grep { $_ eq $ext } $$cfg{FORBIDDEN_EXTENSIONS});
	make_error(S_TOOBIG) if($$cfg{MAX_IMAGE_WIDTH} and $width>$$cfg{MAX_IMAGE_WIDTH});
	make_error(S_TOOBIG) if($$cfg{MAX_IMAGE_HEIGHT} and $height>$$cfg{MAX_IMAGE_HEIGHT});
	make_error(S_TOOBIG) if($$cfg{MAX_IMAGE_PIXELS} and $width*$height>$$cfg{MAX_IMAGE_PIXELS});

	# generate random filename - fudges the microseconds
	my $filebase=$time.sprintf("%03d",int(rand(1000)));
	my $filename=$$cfg{IMG_DIR}.$filebase.'.'.$ext;
	my $thumbnail=$$cfg{THUMB_DIR}.$filebase."s.jpg";
	$filename.=$$cfg{MUNGE_UNKNOWN} unless($known);

	# do copying and MD5 checksum
	my ($md5,$md5ctx,$buffer);

	# prepare MD5 checksum if the Digest::MD5 module is available
	eval 'use Digest::MD5 qw(md5_hex)';
	$md5ctx=Digest::MD5->new unless($@);

	# copy file
	open (OUTFILE,">>$filename") or make_error(S_NOTWRITE);
	binmode OUTFILE;
	while (read($file,$buffer,1024)) # should the buffer be larger?
	{
		print OUTFILE $buffer;
		$md5ctx->add($buffer) if($md5ctx);
	}
	close $file;
	close OUTFILE;

	if($md5ctx) # if we have Digest::MD5, get the checksum
	{
		$md5=$md5ctx->hexdigest();
	}
	else # otherwise, try using the md5sum command
	{
		my $md5sum=`md5sum $filename`; # filename is always the timestamp name, and thus safe
		($md5)=$md5sum=~/^([0-9a-f]+)/ unless($?);
	}

	if($md5) # if we managed to generate an md5 checksum, check for duplicate files
	{
		my $sth=$dbh->prepare("SELECT * FROM ".SQL_TABLE." WHERE md5=?;") or make_error(S_SQLFAIL);
		$sth->execute($md5) or make_error(S_SQLFAIL);

		if(my $match=$sth->fetchrow_hashref())
		{
			unlink $filename; # make sure to remove the file
			make_error(sprintf(S_DUPE,get_reply_link($$match{num},$$match{parent})));
		}
	}

	# do thumbnail
	my ($tn_width,$tn_height,$tn_ext);

	if(!$width) # unsupported file
	{
		if($filetypes{$ext}) # externally defined filetype
		{
			open THUMBNAIL,$filetypes{$ext};
			binmode THUMBNAIL;
			($tn_ext,$tn_width,$tn_height)=analyze_image(\*THUMBNAIL,$filetypes{$ext});
			close THUMBNAIL;

			# was that icon file really there?
			if(!$tn_width) { $thumbnail=undef }
			else { $thumbnail=$filetypes{$ext} }
		}
		else
		{
			$thumbnail=undef;
		}
	}
	elsif($width>$$cfg{MAX_W} or $height>$$cfg{MAX_H} or $$cfg{THUMBNAIL_SMALL})
	{
		if($width<=$$cfg{MAX_W} and $height<=$$cfg{MAX_H})
		{
			$tn_width=$width;
			$tn_height=$height;
		}
		else
		{
			$tn_width=$$cfg{MAX_W};
			$tn_height=int(($height*($$cfg{MAX_W}))/$width);

			if($tn_height>$$cfg{MAX_H})
			{
				$tn_width=int(($width*($$cfg{MAX_H}))/$height);
				$tn_height=$$cfg{MAX_H};
			}
		}

		if($$cfg{STUPID_THUMBNAILING}) { $thumbnail=$filename }
		else
		{
			$thumbnail=undef unless(make_thumbnail($filename,$thumbnail,$tn_width,$tn_height,$$cfg{THUMBNAIL_QUALITY},CONVERT_COMMAND));
		}
	}
	else
	{
		$tn_width=$width;
		$tn_height=$height;
		$thumbnail=$filename;
	}

	if($filetypes{$ext}) # externally defined filetype - restore the name
	{
		my $newfilename=$uploadname;
		$newfilename=~s!^.*[\\/]!!; # cut off any directory in filename
		$newfilename=$$cfg{IMG_DIR}.$newfilename;

		unless(-e $newfilename) # verify no name clash
		{
			rename $filename,$newfilename;
			$thumbnail=$newfilename if($thumbnail eq $filename);
			$filename=$newfilename;
		}
		else
		{
			unlink $filename;
			make_error(S_DUPENAME);
		}
	}

        if(ENABLE_LOAD)
        {       # only called if files to be distributed across web     
                $ENV{SCRIPT_NAME}=~m!^(.*/)[^/]+$!;
		my $root=$1;
                system(LOAD_SENDER_SCRIPT." $filename $root $md5 &");
        }


	return ($filename,$md5,$width,$height,$thumbnail,$tn_width,$tn_height);
}



#
# Deleting
#

sub delete_stuff($$$$@)
{
	my ($sectiom,$password,$fileonly,$archive,$admin,@posts)=@_;
	my ($post);

	check_password($admin,ADMIN_PASS) if($admin);
	make_error(S_BADDELPASS) unless($password or $admin); # refuse empty password immediately

	# no password means delete always
	$password="" if($admin); 

	foreach $post (@posts)
	{
		delete_post($section,$post,$password,$fileonly,$archive);
	}

	# update the cached HTML pages
	build_cache($section);

	if($admin)
	{ make_http_forward(get_script_name()."?admin=$admin&task=mpanel",$$cfg{ALTERNATE_REDIRECT}); }
	else
	{ make_http_forward($$cfg{HTML_SELF},$$cfg{ALTERNATE_REDIRECT}); }
}

sub delete_post($$$$$)
{
	my ($section,$post,$password,$fileonly,$archiving)=@_;
	my ($sth,$row,$res,$reply);
	my $thumb=$$cfg{THUMB_DIR};
	my $archive=$$cfg{ARCHIVE_DIR};
	my $src=$$cfg{IMG_DIR};

	$sth=$dbh->prepare("SELECT * FROM ".SQL_TABLE." WHERE num=? AND section=?;") or make_error(S_SQLFAIL);
	$sth->execute($post,$section) or make_error(S_SQLFAIL);

	if($row=$sth->fetchrow_hashref())
	{
		make_error(S_BADDELPASS) if($password and $$row{password} ne $password);

		unless($fileonly)
		{
			# remove files from comment and possible replies
			$sth=$dbh->prepare("SELECT image,thumbnail FROM ".SQL_TABLE." WHERE (num=? AND section=?) OR parent=?") or make_error(S_SQLFAIL);
			$sth->execute($post,$section,$post) or make_error(S_SQLFAIL);

			while($res=$sth->fetchrow_hashref())
			{
				system(LOAD_SENDER_SCRIPT." $$res{image} &") if(ENABLE_LOAD);
	
				if($archiving)
				{
					# archive images
					rename $$res{image}, $$cfg{ARCHIVE_DIR}.$$res{image};
					rename $$res{thumbnail}, $$cfg{ARCHIVE_DIR}.$$res{thumbnail} if($$res{thumbnail}=~/^$thumb/);
				}
				else
				{
					# delete images if they exist
					unlink $$res{image};
					unlink $$res{thumbnail} if($$res{thumbnail}=~/^$thumb/);
				}
			}

			# remove post and possible replies
			$sth=$dbh->prepare("DELETE FROM ".SQL_TABLE." WHERE (num=? AND section=?) OR parent=?;") or make_error(S_SQLFAIL);
			$sth->execute($post,$section,$post) or make_error(S_SQLFAIL);
		}
		else # remove just the image and update the database
		{
			if($$row{image})
			{
				system(LOAD_SENDER_SCRIPT." $$row{image} &") if(ENABLE_LOAD);

				# remove images
				unlink $$row{image};
				unlink $$row{thumbnail} if($$row{thumbnail}=~/^$thumb/);

				$sth=$dbh->prepare("UPDATE ".SQL_TABLE." SET size=0,md5=null,thumbnail=null WHERE (num=? AND section=?);") or make_error(S_SQLFAIL);
				$sth->execute($posti,$section) or make_error(S_SQLFAIL);
			}
		}

		# fix up the thread cache
		if(!$$row{parent})
		{
			unless($fileonly) # removing an entire thread
			{
				if($archiving)
				{
					my $captcha = $$cfg{CAPTCHA_SCRIPT};
					my $line;

					open RESIN, '<', $$cfg{RES_DIR}.$$row{num}.$$cfg{PAGE_EXT};
					open RESOUT, '>', $$cfg{ARCHIVE_DIR}.$$cfg{RES_DIR}.$$row{num}.$$cfg{PAGE_EXT};
					while($line = <RESIN>)
					{
						$line =~ s/img src="(.*?)$thumb/img src="$1$archive$thumb/g;
						if(ENABLE_LOAD)
						{
							my $redir = $$cfg{REDIR_DIR};
							$line =~ s/href="(.*?)$redir(.*?).html/href="$1$archive$src$2/g;
						}
						else
						{
							$line =~ s/href="(.*?)$src/href="$1$archive$src/g;
						}
						$line =~ s/src="[^"]*$captcha[^"]*"/src=""/g if($$cfg{ENABLE_CAPTCHA});
						print RESOUT $line;	
					}
					close RESIN;
					close RESOUT;
				}
				unlink $$cfg{RES_DIR}.$$row{num}.$$cfg{PAGE_EXT};
			}
			else # removing parent image
			{
				build_thread_cache($section,$$row{num});
			}
		}
		else # removing a reply, or a replys image
		{
			build_thread_cache($section,$$row{parent});
		}
	}
}



#
# Admin interface
#

sub make_admin_login()
{
	make_http_header();
	print encode_string(ADMIN_LOGIN_TEMPLATE->(
		cfg=>$cfg,
		stylesheets=>get_stylesheets($$cfg{DEFAULT_STYLE}, $$cfg{CSS_DIR}),
	));
}

sub make_admin_post_panel($)
{
	my ($admin)=@_;
	my ($sth,$row,@posts,$size,$rowtype);

	check_password($admin,ADMIN_PASS);

	$sth=$dbh->prepare("SELECT * FROM ".SQL_TABLE." ORDER BY lasthit DESC,CASE parent WHEN 0 THEN num ELSE parent END ASC,num ASC;") or make_error(S_SQLFAIL);
	$sth->execute() or make_error(S_SQLFAIL);

	$size=0;
	$rowtype=1;
	while($row=get_decoded_hashref($sth))
	{
		if(!$$row{parent}) { $rowtype=1; }
		else { $rowtype^=3; }
		$$row{rowtype}=$rowtype;

		$size+=$$row{size};

		push @posts,$row;
	}

	make_http_header();
	print encode_string(POST_PANEL_TEMPLATE->(
		cfg=>$cfg,
		stylesheets=>get_stylesheets($$cfg{DEFAULT_STYLE}, $$cfg{CSS_DIR}),
		admin=>$admin,
		posts=>\@posts,
		size=>$size));
}

sub make_admin_ban_panel($)
{
	my ($admin)=@_;
	my ($sth,$row,@bans,$prevtype);

	check_password($admin,ADMIN_PASS);

	$sth=$dbh->prepare("SELECT * FROM ".SQL_ADMIN_TABLE." WHERE type='ipban' OR type='wordban' OR type='whitelist' OR type='trust' ORDER BY type ASC,num ASC;") or make_error(S_SQLFAIL);
	$sth->execute() or make_error(S_SQLFAIL);
	while($row=get_decoded_hashref($sth))
	{
		$$row{divider}=1 if($prevtype ne $$row{type});
		$prevtype=$$row{type};
		$$row{rowtype}=@bans%2+1;
		push @bans,$row;
	}

	make_http_header();
	print encode_string(BAN_PANEL_TEMPLATE->(
		cfg=>$cfg,
		stylesheets=>get_stylesheets($$cfg{DEFAULT_STYLE}, $$cfg{CSS_DIR}),
		admin=>$admin,
		bans=>\@bans
	));
}

sub make_admin_proxy_panel($)
{
	my ($admin)=@_;
	my ($sth,$row,@scanned,$prevtype);

	check_password($admin,ADMIN_PASS);

	proxy_clean();

	$sth=$dbh->prepare("SELECT * FROM ".SQL_PROXY_TABLE." ORDER BY timestamp ASC;") or make_error(S_SQLFAIL);
	$sth->execute() or make_error(S_SQLFAIL);
	while($row=get_decoded_hashref($sth))
	{
		$$row{divider}=1 if($prevtype ne $$row{type});
		$prevtype=$$row{type};
		$$row{rowtype}=@scanned%2+1;
		push @scanned,$row;
	}

	make_http_header();
	print encode_string(PROXY_PANEL_TEMPLATE->(
		cfg=>$cfg,
		stylesheets=>get_stylesheets($$cfg{DEFAULT_STYLE}, $$cfg{CSS_DIR}),
		admin=>$admin,
		scanned=>\@scanned));
}

sub make_admin_spam_panel($)
{
	my ($admin)=@_;
	my @spam_files=SPAM_FILES;
	my @spam=read_array($spam_files[0]);

	check_password($admin,ADMIN_PASS);

	make_http_header();
	print encode_string(SPAM_PANEL_TEMPLATE->(
		cfg=>$cfg,
		stylesheets=>get_stylesheets($$cfg{DEFAULT_STYLE}, $$cfg{CSS_DIR}),
		admin=>$admin,
		spamlines=>scalar @spam,
		spam=>join "\n",map { clean_string($_,1) } @spam
	));
}

sub make_sql_dump($)
{
	my ($admin)=@_;
	my ($sth,$row,@database);

	check_password($admin,ADMIN_PASS);

	$sth=$dbh->prepare("SELECT * FROM ".SQL_TABLE.";") or make_error(S_SQLFAIL);
	$sth->execute() or make_error(S_SQLFAIL);
	while($row=get_decoded_arrayref($sth))
	{
		push @database,"INSERT INTO ".SQL_TABLE." VALUES('".
		(join "','",map { s/\\/&#92;/g; $_ } @{$row}). # escape ' and \, and join up all values with commas and apostrophes
		"');";
	}

	make_http_header();
	print encode_string(SQL_DUMP_TEMPLATE->(
		cfg=>$cfg,
		stylesheets=>get_stylesheets($$cfg{DEFAULT_STYLE}, $$cfg{CSS_DIR}),
		admin=>$admin,
		database=>join "<br />",map { clean_string($_,1) } @database));
}

sub make_sql_interface($$$)
{
	my ($admin,$nuke,$sql)=@_;
	my ($sth,$row,@results);

	check_password($admin,ADMIN_PASS);

	if($sql)
	{
		make_error(S_WRONGPASS) if($nuke ne NUKE_PASS); # check nuke password

		my @statements=grep { /^\S/ } split /\r?\n/,decode_string($sql,$$cfg{CHARSET},1);

		foreach my $statement (@statements)
		{
			push @results,">>> $statement";
			if($sth=$dbh->prepare($statement))
			{
				if($sth->execute())
				{
					while($row=get_decoded_arrayref($sth)) { push @results,join ' | ',@{$row} }
				}
				else { push @results,"!!! ".$sth->errstr() }
			}
			else { push @results,"!!! ".$sth->errstr() }
		}
	}

	make_http_header();
	print encode_string(SQL_INTERFACE_TEMPLATE->(
		cfg=>$cfg,
		stylesheets=>get_stylesheets($$cfg{DEFAULT_STYLE}, $$cfg{CSS_DIR}),
		admin=>$admin,nuke=>$nuke,
		results=>join "<br />",map { clean_string($_,1) } @results));
}

sub make_admin_post($)
{
	my ($admin)=@_;

	check_password($admin,ADMIN_PASS);

	make_http_header();
	print encode_string(ADMIN_POST_TEMPLATE->(
		cfg=>$cfg,
		stylesheets=>get_stylesheets($$cfg{DEFAULT_STYLE}, $$cfg{CSS_DIR}),
		admin=>$admin));
}

sub make_admin_section_panel($$)
{
	my ($admin,$sectionName) = @_;

	check_password($admin,ADMIN_PASS);

	eval { $sectionConfig = fetch_config($dbh,$sectionName); } or make_error(S_INVSECTION);
	
	make_http_header();
	print encode_string(ADMIN_SECTION_TEMPLATE->(
		cfg=>$cfg,
		stylesheets=>get_stylesheets($$cfg{DEFAULT_STYLE}, $$cfg{CSS_DIR}),
		admin=>$admin,
		sectionConfig=>JSON->new->pretty->encode($sectionConfig)));
}

sub do_login($$$$)
{
	my ($password,$nexttask,$savelogin,$admincookie)=@_;
	my $crypt;

	if($password)
	{
		$crypt=crypt_password($password);
	}
	elsif($admincookie eq crypt_password(ADMIN_PASS))
	{
		$crypt=$admincookie;
		$nexttask="mpanel";
	}

	if($crypt)
	{
		if($savelogin and $nexttask ne "nuke")
		{
			make_cookies(wakaadmin=>$crypt,
			-charset=>$$cfg{CHARSET},-autopath=>$$cfg{COOKIE_PATH},-expires=>time+365*24*3600);
		}

		make_http_forward(get_script_name()."?task=$nexttask&admin=$crypt",$$cfg{ALTERNATE_REDIRECT});
	}
	else { make_admin_login() }
}

sub do_logout()
{
	make_cookies(wakaadmin=>"",-expires=>1);
	make_http_forward(get_script_name()."?task=admin",$$cfg{ALTERNATE_REDIRECT});
}

sub do_rebuild_cache($$)
{
	my ($section,$admin)=@_;

	check_password($admin,ADMIN_PASS);

	unlink glob $$cfg{RES_DIR}.'*';

	repair_database();
	build_thread_cache_all($section);
	build_cache($section);

	make_http_forward($$cfg{HTML_SELF},$$cfg{ALTERNATE_REDIRECT});
}

sub add_admin_entry($$$$$$)
{
	my ($admin,$type,$comment,$ival1,$ival2,$sval1)=@_;
	my ($sth);

	check_password($admin,ADMIN_PASS);

	$comment=clean_string(decode_string($comment,$$cfg{CHARSET}));

	$sth=$dbh->prepare("INSERT INTO ".SQL_ADMIN_TABLE." VALUES(null,?,?,?,?,?);") or make_error(S_SQLFAIL);
	$sth->execute($type,$comment,$ival1,$ival2,$sval1) or make_error(S_SQLFAIL);

	make_http_forward(get_script_name()."?admin=$admin&task=bans",$$cfg{ALTERNATE_REDIRECT});
}

sub remove_admin_entry($$)
{
	my ($admin,$num)=@_;
	my ($sth);

	check_password($admin,ADMIN_PASS);

	$sth=$dbh->prepare("DELETE FROM ".SQL_ADMIN_TABLE." WHERE num=?;") or make_error(S_SQLFAIL);
	$sth->execute($num) or make_error(S_SQLFAIL);

	make_http_forward(get_script_name()."?admin=$admin&task=bans",$$cfg{ALTERNATE_REDIRECT});
}

sub delete_all($$$$)
{
	# TODO Allow delete all messages from whole board or concrete section
	my ($section,$admin,$ip,$mask)=@_;
	my ($sth,$row,@posts);

	check_password($admin,ADMIN_PASS);

	$sth=$dbh->prepare("SELECT num FROM ".SQL_TABLE." WHERE ip & ? = ? & ? AND section = ?;") or make_error(S_SQLFAIL);
	$sth->execute($mask,$ip,$mask,$section) or make_error(S_SQLFAIL);
	while($row=$sth->fetchrow_hashref()) { push(@posts,$$row{num}); }

	delete_stuff($section,'',0,0,$admin,@posts);
}

sub update_spam_file($$)
{
	my ($admin,$spam)=@_;

	check_password($admin,ADMIN_PASS);

	my @spam=split /\r?\n/,$spam;
	my @spam_files=SPAM_FILES;
	write_array($spam_files[0],@spam);

	make_http_forward(get_script_name()."?admin=$admin&task=spam",$$cfg{ALTERNATE_REDIRECT});
}

sub do_nuke_database($)
{
	my ($admin)=@_;

	check_password($admin,NUKE_PASS);

	init_database();
	#init_admin_database();
	#init_proxy_database();

	# remove images, thumbnails and threads
	unlink glob $$cfg{IMG_DIR}.'*';
	unlink glob $$cfg{THUMB_DIR}.'*';
	unlink glob $$cfg{RES_DIR}.'*';

	build_cache($boardSection);

	make_http_forward($$cfg{HTML_SELF},$$cfg{ALTERNATE_REDIRECT});
}

sub do_update_sectioncfg($$$)
{
	my ($admin,$sectionName,$sectionConfig) = @_;
	my ($decodedConfig);

	check_password($admin,ADMIN_PASS);

	$decodedConfig = decode_json($sectionConfig);
	store_config($sectionName,$decodedConfig);

	make_http_forward($$cfg{HTML_SELF},$$cfg{ALTERNATE_REDIRECT});
}

sub check_password($$)
{
	my ($admin,$password)=@_;

	return if($admin eq ADMIN_PASS);
	return if($admin eq crypt_password($password));

	make_error(S_WRONGPASS);
}

sub crypt_password($)
{
	my $crypt=hide_data((shift).$ENV{REMOTE_ADDR},9,"admin",SECRET,1);
	$crypt=~tr/+/./; # for web shit
	return $crypt;
}



#
# Page creation utils
#

sub make_http_error($$)
{
	my ($status,$error) = @_;
	print header(
		-typt=>'text/html',
		-status=>$status);

	print encode_string(ERROR_TEMPLATE->(
		cfg=>$cfg,
		stylesheets=>get_stylesheets($$cfg{DEFAULT_STYLE}, $$cfg{CSS_DIR}),
		error=>($error or $status)));

	eval { next; };
	if ($@) {
		exit(0);
	}	
}

sub make_http_header()
{
	print "Content-Type: ".get_xhtml_content_type($$cfg{CHARSET},$$cfg{USE_XHTML})."\n";
	print "\n";
}

sub make_error($)
{
	my ($error)=@_;

	make_http_header();

	print encode_string(ERROR_TEMPLATE->(
		cfg=>$cfg,
		stylesheets=>get_stylesheets($$cfg{DEFAULT_STYLE}, $$cfg{CSS_DIR}),
		error=>$error));

	if($dbh)
	{
		# TODO Free connection back to pool here
	}

	if(ERRORLOG) # could print even more data, really.
	{
		open ERRORFILE,'>>'.ERRORLOG;
		print ERRORFILE $error."\n";
		print ERRORFILE $ENV{HTTP_USER_AGENT}."\n";
		print ERRORFILE "**\n";
		close ERRORFILE;
	}

	# delete temp files

	eval { next; };
	if ($@) {
		exit(0);
	}	
}

sub get_script_name()
{
	return $ENV{SCRIPT_NAME};
}

sub get_secure_script_name()
{
	return 'https://'.$ENV{SERVER_NAME}.$ENV{SCRIPT_NAME} if($$cfg{USE_SECURE_ADMIN});
	return $ENV{SCRIPT_NAME};
}

sub expand_image_filename($)
{
	my $filename=shift;

	return expand_filename(clean_path($filename)) unless ENABLE_LOAD;

	my ($self_path)=$ENV{SCRIPT_NAME}=~m!^(.*/)[^/]+$!;
	my $src=$$cfg{IMG_DIR};
	$filename=~/$src(.*)/;
	return $self_path.$$cfg{REDIR_DIR}.clean_path($1).'.html';
}

sub get_reply_link($$)
{
	my ($reply,$parent)=@_;

	return expand_filename($$cfg{RES_DIR}.$parent.$$cfg{PAGE_EXT}).'#'.$reply if($parent);
	return expand_filename($$cfg{RES_DIR}.$reply.$$cfg{PAGE_EXT});
}

sub get_page_count(;$)
{
	my $total=(shift or count_threads());
	return int(($total+$$cfg{IMAGES_PER_PAGE}-1)/$$cfg{IMAGES_PER_PAGE});
}

sub get_filetypes()
{
	my %filetypes=FILETYPES;
	$filetypes{gif}=$filetypes{jpg}=$filetypes{png}=1;
	return join ", ",map { uc } sort keys %filetypes;
}

sub dot_to_dec($)
{
	return unpack('N',pack('C4',split(/\./, $_[0]))); # wow, magic.
}

sub dec_to_dot($)
{
	return join('.',unpack('C4',pack('N',$_[0])));
}

sub parse_range($$)
{
	my ($ip,$mask)=@_;

	$ip=dot_to_dec($ip) if($ip=~/^\d+\.\d+\.\d+\.\d+$/);

	if($mask=~/^\d+\.\d+\.\d+\.\d+$/) { $mask=dot_to_dec($mask); }
	elsif($mask=~/(\d+)/) { $mask=(~((1<<$1)-1)); }
	else { $mask=0xffffffff; }

	return ($ip,$mask);
}




#
# Database utils
#

sub init_database()
{
	my ($sth);
	
	eval { $dbh->do("DROP TABLE ".SQL_TABLE.";") } or do {};
	eval { $dbh->do("DROP TABLE ".SQL_COUNTERS_TABLE.";") } or do {};


	eval {
		$dbh->begin_work();

		$sth=$dbh->prepare("CREATE TABLE ".SQL_TABLE." (".

		"parent INTEGER,".			# Parent post for replies in threads. For original posts, must be set to 0 (and not null)
		"timestamp INTEGER,".	 		# Timestamp in seconds for when the post was created
		"lasthit INTEGER,".			# Last activity in thread. Must be set to the same value for BOTH the original post and all replies!
		"ip ".get_sql_ip().",".			# IP number of poster, in integer form!

		"date TEXT,".				# The date, as a string
		"name TEXT,".				# Name of the poster
		"trip TEXT,".				# Tripcode (encoded)
		"email TEXT,".				# Email address
		"subject TEXT,".			# Subject
		"password TEXT,".			# Deletion password (in plaintext) 
		"comment TEXT,".			# Comment text, HTML encoded.

		"image TEXT,".				# Image filename with path and extension (IE, src/1081231233721.jpg)
		"size INTEGER,".			# File size in bytes
		"md5 TEXT,".				# md5 sum in hex
		"width INTEGER,".			# Width of image in pixels
		"height INTEGER,".			# Height of image in pixels
		"thumbnail TEXT,".			# Thumbnail filename with path and extension
		"tn_width TEXT,".			# Thumbnail width in pixels
		"tn_height TEXT,".			# Thumbnail height in pixels
		"section CHAR(64),".			# Board section
		"num INTEGER".				# Post number, retreive it from counters
		");");
		$sth->execute();

		$sth=$dbh->prepare("CREATE TABLE ".SQL_COUNTERS_TABLE." (".
		"section CHAR(64),".			# Board section
		"counter INTEGER".			# Messages counter
		");");
		$sth->execute();

		$sth=$dbh->prepare("INSERT INTO ".SQL_COUNTERS_TABLE." VALUES (?,?);");
		$sth->execute($boardSection,0);

		$dbh->commit();
	};
	if ($@) {
		$dbh->rollback();
		make_error(S_SQLFAIL);
	}
}

sub init_admin_database()
{
	my ($sth);

	eval { $dbh->do("DROP TABLE ".SQL_ADMIN_TABLE.";") } or do { };

	$sth=$dbh->prepare("CREATE TABLE ".SQL_ADMIN_TABLE." (".

	"num ".get_sql_autoincrement().",".	# Entry number, auto-increments
	"type TEXT,".				# Type of entry (ipban, wordban, etc)
	"comment TEXT,".			# Comment for the entry
	"ival1 ".get_sql_ip().",".		# Integer value 1 (usually IP)
	"ival2 ".get_sql_ip().",".		# Integer value 2 (usually netmask)
	"sval1 TEXT".				# String value 1

	");") or make_error(S_SQLFAIL);
	$sth->execute() or make_error(S_SQLFAIL);
}

sub init_proxy_database()
{
	my ($sth);

	eval { $dbh->do("DROP TABLE ".SQL_PROXY_TABLE.";") } or do { }; 

	$sth=$dbh->prepare("CREATE TABLE ".SQL_PROXY_TABLE." (".

	"num ".get_sql_autoincrement().",".	# Entry number, auto-increments
	"type TEXT,".				# Type of entry (black, white, etc)
	"ip ".get_sql_ip().",".					# IP address
	"timestamp INTEGER,".			# Age since epoch
	"date TEXT".				# Human-readable form of date 

	");") or make_error(S_SQLFAIL);
	$sth->execute() or make_error(S_SQLFAIL);
}

sub init_settings_database() 
{
	my ($sth);

	eval { $dbh->do("DROP TABLE ".SQL_SETTINGS_TABLE.";") } or do { }; 

	eval {
		$dbh->begin_work();
		$sth=$dbh->prepare("CREATE TABLE ".SQL_SETTINGS_TABLE." (".
			"section  char(40),".				# Section name (b for /b/, s for /s/)
			"settings TEXT".				# Settings in json format
		");");
		$sth->execute();

		$sth=$dbh->prepare("INSERT INTO ".SQL_SETTINGS_TABLE." VALUES ('', ?);"); 
		$sth->execute(encode_json($default_settings));

		$sth=$dbh->prepare("INSERT INTO ".SQL_SETTINGS_TABLE." VALUES ('default', ?);"); 
		$sth->execute(encode_json($default_settings));
		$dbh->commit();
	};
	if ($@) {
		print $@;
		eval { $dbh->rollback(); };
		make_error(S_SQLFAIL);
	}
	
}

sub repair_database()
{
	# TODO Учитывать новые таблички
	my ($sth,$row,@threads,$thread);

	$sth=$dbh->prepare("SELECT * FROM ".SQL_TABLE." WHERE parent=0;") or make_error(S_SQLFAIL);
	$sth->execute() or make_error(S_SQLFAIL);

	while($row=$sth->fetchrow_hashref()) { push(@threads,$row); }

	foreach $thread (@threads)
	{
		# fix lasthit
		my ($upd);

		$upd=$dbh->prepare("UPDATE ".SQL_TABLE." SET lasthit=? WHERE parent=? AND section=?;") or make_error(S_SQLFAIL);
		$upd->execute($$thread{lasthit},$$thread{num},$$thread{section}) or make_error(S_SQLFAIL." ".$dbh->errstr());
	}
}

sub get_sql_autoincrement()
{
	return 'SERIAL PRIMARY KEY' if(SQL_DBI_SOURCE=~/^DBI:Pg:/i);
	return 'INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT' if(SQL_DBI_SOURCE=~/^DBI:mysql:/i);
	return 'INTEGER PRIMARY KEY' if(SQL_DBI_SOURCE=~/^DBI:SQLite:/i);
	return 'INTEGER PRIMARY KEY' if(SQL_DBI_SOURCE=~/^DBI:SQLite2:/i);

	make_error(S_SQLCONF); # maybe there should be a sane default case instead?
}

sub get_sql_ip()
{
	return 'bigint' if(SQL_DBI_SOURCE=~/^DBI:Pg:/i);
	return 'TEXT' if(SQL_DBI_SOURCE=~/^DBI:mysql:/i);
	return 'TEXT' if(SQL_DBI_SOURCE=~/^DBI:SQLite:/i);
	return 'TEXT' if(SQL_DBI_SOURCE=~/^DBI:SQLite2:/i);

	make_error(S_SQLCONF); # maybe there should be a sane default case instead?
}

sub fetch_config($$)
{
	my ($dbh,$boardSection) = @_;
	my ($sth,$row);

	$sth=$dbh->prepare("SELECT * FROM ".SQL_SETTINGS_TABLE." WHERE section=?;") or make_error(S_SQLFAIL);
	$sth->execute($boardSection) or make_error(S_SQLFAIL);

	$row=$sth->fetchrow_hashref();
	return decode_json($$row{settings});
}

sub store_config($$)
{
	my ($sectionName,$configToStore) = @_;
	my ($sth);

	eval { 
		$sth=$dbh->prepare("DELETE FROM ".SQL_SETTINGS_TABLE." WHERE section=?;"); 
		$sth->execute($sectionName);
	} or do { };
	eval {
		$dbh->begin_work();
		$sth=$dbh->prepare("INSERT INTO ".SQL_SETTINGS_TABLE." VALUES (?, ?);"); 
		$sth->execute($sectionName, encode_json($configToStore));
		$dbh->commit();
	};
	if ($@) {
		eval { $dbh->rollback(); };
		make_error(S_SQLFAIL);
	}

}

sub trim_database($)
{
	my ($section) = @_;
	my ($sth,$row,$order);

	if($$cfg{TRIM_METHOD}==0) { $order='num ASC'; }
	else { $order='lasthit ASC'; }

	if($$cfg{MAX_AGE}) # needs testing
	{
		my $mintime=time()-($$cfg{MAX_AGE})*3600;

		$sth=$dbh->prepare("SELECT * FROM ".SQL_TABLE." WHERE parent=0 AND timestamp<=$mintime AND section=?;") or make_error(S_SQLFAIL);
		$sth->execute($section) or make_error(S_SQLFAIL);

		while($row=$sth->fetchrow_hashref())
		{
			delete_post($section,$$row{num},"",0,$$cfg{ARCHIVE_MODE});
		}
	}

	my $threads=count_threads();
	my ($posts,$size)=count_posts();
	my $max_threads=($$cfg{MAX_THREADS} or $threads);
	my $max_posts=($$cfg{MAX_POSTS} or $posts);
	my $max_size=($$cfg{MAX_MEGABYTES}*1024*1024 or $size);

	while($threads>$max_threads or $posts>$max_posts or $size>$max_size)
	{
		$sth=$dbh->prepare("SELECT * FROM ".SQL_TABLE." WHERE parent=0 AND section=? ORDER BY $order LIMIT 1;") or make_error(S_SQLFAIL);
		$sth->execute($section) or make_error(S_SQLFAIL);

		if($row=$sth->fetchrow_hashref())
		{
			my ($threadposts,$threadsize)=count_posts($$row{num});

			delete_post($section,$$row{num},"",0,$$cfg{ARCHIVE_MODE});

			$threads--;
			$posts-=$threadposts;
			$size-=$threadsize;
		}
		else { last; } # shouldn't happen
	}
}

sub table_exists($)
{
	my ($table)=@_;
   	eval { $dbh->do("SELECT * FROM ".$table." LIMIT 1;") } or do { return 0 };
	return 1
}

sub count_threads()
{
	my ($sth);

	$sth=$dbh->prepare("SELECT count(*) FROM ".SQL_TABLE." WHERE parent=0;") or make_error(S_SQLFAIL);
	$sth->execute() or make_error(S_SQLFAIL);

	return ($sth->fetchrow_array())[0];
}

sub count_posts(;$)
{
	my ($parent)=@_;
	my ($sth,$where);

	$where="WHERE parent=$parent or num=$parent" if($parent);
	$sth=$dbh->prepare("SELECT count(*),sum(size) FROM ".SQL_TABLE." $where;") or make_error(S_SQLFAIL);
	$sth->execute() or make_error(S_SQLFAIL);

	return $sth->fetchrow_array();
}

sub thread_exists($)
{
	my ($thread)=@_;
	my ($sth);

	$sth=$dbh->prepare("SELECT count(*) FROM ".SQL_TABLE." WHERE num=? AND parent=0;") or make_error(S_SQLFAIL);
	$sth->execute($thread) or make_error(S_SQLFAIL);

	return ($sth->fetchrow_array())[0];
}

sub get_decoded_hashref($)
{
	my ($sth)=@_;

	my $row=$sth->fetchrow_hashref();

	if($row and $has_encode)
	{
		for my $k (keys %$row) # don't blame me for this shit, I got this from perlunicode.
		{ defined && /[^\000-\177]/ && Encode::_utf8_on($_) for $row->{$k}; }

		if(SQL_DBI_SOURCE=~/^DBI:mysql:/i) # OMGWTFBBQ
		{ for my $k (keys %$row) { $$row{$k}=~s/chr\(([0-9]+)\)/chr($1)/ge; } }
	}

	return $row;
}

sub get_decoded_arrayref($)
{
	my ($sth)=@_;

	my $row=$sth->fetchrow_arrayref();

	if($row and $has_encode)
	{
		# don't blame me for this shit, I got this from perlunicode.
		defined && /[^\000-\177]/ && Encode::_utf8_on($_) for @$row;

		if(SQL_DBI_SOURCE=~/^DBI:mysql:/i) # OMGWTFBBQ
		{ s/chr\(([0-9]+)\)/chr($1)/ge for @$row; }
	}

	return $row;
}

#
# Section dealing utils
#
sub init_section($)
{
	my ($sectionName) = @_;
	my ($prefix);

	make_error(S_INVSECTION) if ($sectionName !~ /\w+/);

	# Creating directory structure for new board section	
	mkdir(FILESYSTEM_ROOT.$sectionName, 		0755);
	mkdir(FILESYSTEM_ROOT.$sectionName."/res/", 	0755);
	mkdir(FILESYSTEM_ROOT.$sectionName."/src/", 	0755);
	mkdir(FILESYSTEM_ROOT.$sectionName."/thumb/", 	0755);

	$configTemplate = fetch_config($dbh,'');
	$prefix = "/$sectionName/";

	# Adjusting config values
	$configTemplate{IMG_DIR} 	= $prefix.$configTemplate{IMG_DIR};
	$configTemplate{THUMB_DIR} 	= $prefix.$configTemplate{THUMB_DIR};
	$configTemplate{RES_DIR} 	= $prefix.$configTemplate{RES_DIR};
	$configTemplate{ARCH_DIR} 	= $prefix.$configTemplate{ARCH_DIR};
	$configTemplate{REDIR_DIR} 	= $prefix.$configTemplate{REDIR_DIR};
	$configTemplate{SCRIPT_NAME} 	= $prefix.$configTemplate{SCRIPT_NAME};
	$configTemplate{CAPTCHA_SCRIPT} = $prefix.$configTemplate{CAPTCHA_SCRIPT};
	
	store_config($sectionName,$configTemplate);
}
