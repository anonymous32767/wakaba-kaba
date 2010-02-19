use encoding "shift-jis";

use constant S_HOME => '�z�[��';
use constant S_ADMIN => '�Ǘ��p';
use constant S_RETURN => '�f���ɖ߂�';
use constant S_POSTING => '���X���M���[�h';

use constant S_NAME => '���Ȃ܂�';
use constant S_EMAIL => 'E-mail';
use constant S_SUBJECT => '��@�@��';
use constant S_SUBMIT => '���M����';
use constant S_COMMENT => '�R�����g';
use constant S_UPLOADFILE => '�Y�tFile';
use constant S_NOFILE => '�摜�Ȃ�';
use constant S_CAPTCHA => '����';
use constant S_PARENT => '�X��';
use constant S_DELPASS => '�폜�L�[';
use constant S_DELEXPL => '(�L���̍폜�p�B�p������8�����ȓ�)';
use constant S_SPAMTRAP => 'Leave these fields empty (spam trap): ';

use constant S_THUMB => '�T���l�C����\�����Ă��܂�.�N���b�N����ƌ��̃T�C�Y��\�����܂�.';
use constant S_HIDDEN => 'Image reply hidden, click name for full image.';
use constant S_NOTHUMB => 'No<br />thumbnail';
use constant S_PICNAME => '�摜�^�C�g���F';
use constant S_REPLY => '�ԐM';
use constant S_OLD => '���̃X���͌Â��̂ŁA�������������܂��B';
use constant S_ABBR => '���X%d���ȗ��B�S�ēǂނɂ͕ԐM�{�^���������Ă��������B';
use constant S_ABBRIMG => '���X%d,%d���ȗ��B�S�ēǂނɂ͕ԐM�{�^���������Ă��������B';
use constant S_ABBRTEXT => '�ȗ�����܂����E�E�S�Ă�ǂނɂ�<a href="%s">����</a>�������Ă�������';

use constant S_REPDEL => '�y�L���폜�z';
use constant S_DELPICONLY => '�摜��������';
use constant S_DELKEY => '�폜�L�[';
use constant S_DELETE => '�폜';

use constant S_PREV => '�O�̃y�[�W';
use constant S_FIRSTPG => '�ŏ��̃y�[�W';
use constant S_NEXT => '���̃y�[�W';
use constant S_LASTPG => '�Ō�̃y�[�W';

use constant S_WEEKDAYS => ('��','��','��','��','��','��','�y');

use constant S_MANARET => '�f���ɖ߂�';
use constant S_MANAMODE => '�Ǘ����[�h';

use constant S_MANALOGIN => 'Manager Login';
use constant S_ADMINPASS => 'Admin password:';

use constant S_MANAPANEL => '�L���폜';
use constant S_MANABANS => 'Bans';
use constant S_MANAPROXY => 'Proxy Panel';
use constant S_MANASPAM => '�X�p��';
use constant S_MANASQLDUMP => 'SQL Dump';
use constant S_MANASQLINT=> 'SQL Interface';
use constant S_MANAPOST => '�Ǘ��l���e';
use constant S_MANAREBUILD => '�L���b�V���̍č\�z';
use constant S_MANANUKE => 'Nuke board';
use constant S_MANALOGOUT => 'Log out';									# 
use constant S_MANASAVE => 'Remember me on this computer';				# Defines Label for the login cookie checbox
use constant S_MANASUB => ' �F��';

use constant S_NOTAGS => '�^�O�������܂�';

use constant S_MPDELETEIP => 'Delete all';
use constant S_MPDELETE => '�폜����';
use constant S_MPARCHIVE => 'Archive';
use constant S_MPRESET => '���Z�b�g';
use constant S_MPONLYPIC => '�摜��������';
use constant S_MPDELETEALL => 'Del all';
use constant S_MPBAN => 'Ban';
use constant S_MPTABLE => '<th>Post No.</th><th>Time</th><th>Subject</th>'.
                          '<th>Name</th><th>Comment</th><th>IP</th>';
use constant S_IMGSPACEUSAGE => '�y �摜�f�[�^���v : <b>%d</b> KB �z';

use constant S_BANTABLE => '<th>Type</th><th>Value</th><th>Comment</th><th>Action</th>';
use constant S_BANIPLABEL => 'IP';
use constant S_BANMASKLABEL => 'Mask';
use constant S_BANCOMMENTLABEL => 'Comment';
use constant S_BANWORDLABEL => 'Word';
use constant S_BANIP => 'Ban IP';
use constant S_BANWORD => 'Ban word';
use constant S_BANWHITELIST => 'Whitelist';
use constant S_BANREMOVE => 'Remove';
use constant S_BANCOMMENT => 'Comment';
use constant S_BANTRUST => 'No captcha';
use constant S_BANTRUSTTRIP => 'Tripcode';

use constant S_PROXYTABLE => '<th>Type</th><th>IP</th><th>Expires</th><th>Date</th>'; # Explains names for Proxy Panel
use constant S_PROXYIPLABEL => 'IP';
use constant S_PROXYTIMELABEL => 'Seconds to live';
use constant S_PROXYREMOVEBLACK => 'Remove';
use constant S_PROXYWHITELIST => 'Whitelist';
use constant S_PROXYDISABLED => 'Proxy detection is currently disabled in configuration.';
use constant S_BADIP => 'Bad IP value';

use constant S_SPAMEXPL => 'This is the list of domain names Wakaba considers to be spam.<br />'.
                           'You can find an up-to-date version <a href="http://wakaba.c3.cx/antispam/antispam.pl?action=view&format=wakaba">here</a>, '.
                           'or you can get the <code>spam.txt</code> file directly <a href="http://wakaba.c3.cx/antispam/spam.txt">here</a>.';
use constant S_SPAMSUBMIT => 'Save';
use constant S_SPAMCLEAR => 'Clear';
use constant S_SPAMRESET => 'Restore';

use constant S_SQLNUKE => 'Nuke password:';
use constant S_SQLEXECUTE => 'Execute';

use constant S_TOOBIG => '�A�b�v���[�h�Ɏ��s���܂���<br />�T�C�Y���傫�����܂�<br />'.MAX_KB.'K�o�C�g�܂�';
use constant S_TOOBIGORNONE => '�A�b�v���[�h�Ɏ��s���܂���<br />�摜�T�C�Y���傫�����邩�A<br />�܂��͉摜������܂���B';
use constant S_REPORTERR => '�Y���L�����݂���܂���';
use constant S_UPFAIL => '�A�b�v���[�h�Ɏ��s���܂���<br />�T�[�o���T�|�[�g���Ă��Ȃ��\��������܂�';
use constant S_NOREC => '�A�b�v���[�h�Ɏ��s���܂���<br />�摜�t�@�C���ȊO�͎󂯕t���܂���';
use constant S_NOCAPTCHA => 'Error: No verification code on record - it probably timed out.';
use constant S_BADCAPTCHA => '�s���Ȍ��؃R�[�h�����͂���܂���';
use constant S_BADFORMAT => 'Error: File format not supported.';
use constant S_STRREF => '���₳��܂���(str)';
use constant S_UNJUST => '�s���ȓ��e�����Ȃ��ŉ�����(post)';
use constant S_NOPIC => '�摜������܂���';
use constant S_NOTEXT => '���������ĉ�����';
use constant S_TOOLONG => '�{�����������܂����I';
use constant S_NOTALLOWED => '�Ǘ��l�ȊO�͓��e�ł��܂���';
use constant S_UNUSUAL => '�ُ�ł�';
use constant S_BADHOST => '���₳��܂���(host)';
use constant S_BADHOSTPROXY => 'Error: Proxy is banned for being open.';				# Returns error for banned proxy ($badip string)
use constant S_RENZOKU => '�A�����e�͂������΂炭���Ԃ�u���Ă��炨�肢�v���܂�';
use constant S_RENZOKU2 => '�摜�A�����e�͂������΂炭���Ԃ�u���Ă��炨�肢�v���܂�';
use constant S_RENZOKU3 => '�A�����e�͂������΂炭���Ԃ�u���Ă��炨�肢�v���܂�';
use constant S_PROXY => '�d�q�q�n�q�I�@���J�o�q�n�w�x�K�����I�I(%d)';
use constant S_DUPE => '�A�b�v���[�h�Ɏ��s���܂���<br />�����摜������܂� (<a href="%s">link</a>)';
use constant S_DUPENAME => 'Error: A file with the same name already exists.';
use constant S_NOTHREADERR => '�X���b�h������܂���';
use constant S_BADDELPASS => '�Y���L����������Ȃ����p�X���[�h���Ԉ���Ă��܂�';
use constant S_WRONGPASS => '�p�X���[�h���Ⴂ�܂�';
use constant S_NOTWRITE => '�������܂���<br />';
use constant S_SPAM => '�X�p���𓊍e���Ȃ��ŉ�����';					# Returns error when detecting spam

use constant S_SQLCONF => '�ڑ����s';
use constant S_SQLFAIL => 'sql���s';

use constant S_REDIR => 'If the redirect didn\'t work, please choose one of the following mirrors:';    # Redir message for html in REDIR_DIR

#define(S_ANONAME, '������');
#define(S_ANOTEXT, '�{���Ȃ�');
#define(S_ANOTITLE, '����');
#use constant S_MPTITLE => '�폜�������L���̃`�F�b�N�{�b�N�X�Ƀ`�F�b�N�����A�폜�{�^���������ĉ������B';
#define(S_MDTABLE1, '<th>�폜</th><th>�L��No</th><th>���e��</th><th>�薼</th>');
#define(S_MDTABLE2, '<th>���e��</th><th>�R�����g</th><th>�z�X�g��</th><th>�Y�t<br />(Bytes)</th><th>md5</th>');

no encoding;
1;
