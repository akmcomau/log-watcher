#!/usr/local/bin/perl

package AKM::Logwatcher;

use Modern::Perl;
use Moose;

use Data::Dumper;

use File::Touch;
use File::Slurp;
use File::Tail::Multi;
use YAML;
use JSON;
use BSON qw/encode decode/;
use DateTime;
use Time::Local;
use Sys::Syslog;

with qw(MooseX::Daemonize);

has 'binary_json'     => (is=>'ro', isa=>'Bool', default=>0);

has 'logger'          => (is=>'rw', isa=>'Ref', required=>1);

has 'mode'            => (is=>'rw', isa=>'Maybe[Str]', default=>undef);
has 'tail_mode'       => (is=>'rw', isa=>'Bool', default=>0);
has 'ban_mode'        => (is=>'rw', isa=>'Bool', default=>0);

has 'test_log_file'   => (is=>'ro', isa=>'Maybe[Str]', default=>undef);
has 'config'          => (is=>'rw', isa=>'HashRef', default=>sub{ {} });
has 'state'           => (is=>'rw', isa=>'HashRef', default=>sub{ {} });

has 'config_file'     => (is=>'ro', isa=>'Str', default=>$ENV{'HOME'}.'/.logwatcher/rules');
has 'state_file'      => (is=>'ro', isa=>'Str', default=>$ENV{'HOME'}.'/.logwatcher/state');
has 'last_run_file'   => (is=>'rw', isa=>'Maybe[Str]', default=>$ENV{'HOME'}.'/.logwatcher/lastrun');

has 'num_tail_lines'  => (is=>'rw', isa=>'Int', default=>10);
has 'only_coloured'   => (is=>'rw', isa=>'Bool', default=>0);
has 'follow_tail'     => (is=>'rw', isa=>'Bool', default=>0);

has 'sort_lines'      => (is=>'rw', isa=>'Bool', default=>0);
has 'sort_lines_once' => (is=>'rw', isa=>'Bool', default=>0);

has 'iptables'        => (is=>'rw', isa=>'Str', default=>'/sbin/iptables');
has 'iptables_chain'  => (is=>'rw', isa=>'Str', default=>'Firewall-Logwatcher-Banned');

has 'whitelist_ips'   => (is=>'rw', isa=>'HashRef',  default=>sub{ {} });
has 'log_file_lookup' => (is=>'rw', isa=>'HashRef',  default=>sub{ {} });
has 'log_files'       => (is=>'rw', isa=>'ArrayRef', default=>sub{ [] });

has 'date_vars'       => (is=>'rw', isa=>'ArrayRef', default=>sub{ [qw (Y M m d h i s)] });
has 'date_rules'      => (is=>'rw', isa=>'HashRef', default=>sub{ {} });

has 'just_banned'       => (is=>'rw', isa=>'HashRef', default=>sub{ {} });
has 'last_just_banned'  => (is=>'rw', isa=>'HashRef', default=>sub{ {} });

has 'state_changed'     => (is=>'rw', isa=>'Bool', default=>0);

my $logwatcher_object;

# the month abbreviations
my %months_abbrev = (
	'Jan' => 0,
	'Feb' => 1,
	'Mar' => 2,
	'Apr' => 3,
	'May' => 4,
	'Jun' => 5,
	'Jul' => 6,
	'Aug' => 7,
	'Sep' => 8,
	'Oct' => 9,
	'Nov' => 10,
	'Dec' => 11,
);

# use iptables to ban an ip address
sub iptables_ban {
	my ($self, $ip, $reason) = @_;
	my $ip_str = $self->int_to_ip($ip);

	if ($self->just_banned->{$ip} || $self->last_just_banned->{$ip}) {
		$self->logger->debug("Skipping [$ip_str: $reason] was just banned");
		return 0;
	}
	$self->just_banned->{$ip} = 1;

	# if they are already banned then don't action
	if (defined($self->whitelist_ips->{$ip_str})) {
		$self->logger->info("Not banning allowed ip: ".$ip_str);
		return 0;
	}

	$self->logger->info("Banning $ip_str: $reason");
	$self->tail_print('bold-red', "***** Banning $ip_str: $reason *****") if $logwatcher_object->tail_mode;
	my $cmd = $self->iptables." -A ".$self->iptables_chain." -s $ip_str -j DROP";
	system $cmd;

	# print the iptables info
	if ($self->logger->is_debug) {
		$self->logger->debug('Ban: '.$cmd);
		my @output = `${self->iptables} -L -v`;
		$self->logger->debug(@output);
	}

	return 1;
}

# use iptables to unban an ip address
sub iptables_unban {
	my ($self, $ip) = @_;
	my $ip_str = $self->int_to_ip($ip);

	$self->logger->info("UnBanning: $ip_str");
	my $cmd = $self->iptables." -D ".$self->iptables_chain." -s $ip_str -j DROP";
	system $cmd;

	# print the iptables info
	if ($self->logger->is_debug) {
		$self->logger->debug('Unban: '.$cmd);
		my @output = `${self->iptables} -L -v`;
		$self->logger->debug(@output);
	}

	return 1;
}

# convert an ip address to an integer
sub ip_to_int {
	my ($self, $ip) = @_;

	if ($ip =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/) {
		return (int($1) << 24) | (int($2) << 16) | (int($3) << 8) | int($4);
	}
	return undef;
}

# convert an integer to an ip address
sub int_to_ip {
	my ($self, $ip) = @_;

	my $string = '';
	$string .= int(((0xFF << 24) & $ip) >> 24) . ".";
	$string .= int(((0xFF << 16) & $ip) >> 16) . ".";
	$string .= int(((0xFF << 8) & $ip) >> 8) . ".";
	$string .= int(0xFF & $ip);

	return $string;
}

sub load_state {
	my ($self) = @_;

	unless (-e $self->state_file) {
		$self->state({});
		return;
	}

	# open the file
	my %file_options;
	if ($self->binary_json) {
		$file_options{'binmode'} = ':raw';
	}
	my $file_contents = read_file($self->state_file, %file_options);

	if ($self->binary_json) {
		$self->state(decode($file_contents)) or die "Could not decode state file";
	}
	else {
		$self->state(decode_json($file_contents)) or die "Could not decode state file";
	}
}

sub save_state {
	my ($self) = @_;

	my $file_contents;
	if ($self->binary_json) {
		$file_contents = encode($self->state);
	}
	else {
		$file_contents = encode_json($self->state);
	}

	if (!$file_contents) {
		$self->logger->error("Could not encode state file");
		return;
	}

	# write the file
	my %file_options;
	if ($self->binary_json) {
		$file_options{'binmode'} = ':raw';
	}
	write_file($self->state_file, \%file_options, $file_contents)
		or $self->logger->error("Could not write state_file");
}

sub load_config {
	my ($self) = @_;

	# load the config
	my $file_contents = read_file($self->config_file);
	eval {
		$self->config(Load($file_contents));
	};
	if ($@) {
		die "Could not decode config file: $@";
	}

	# whitelisted IP address
	#   Hash for fast lookup, if a large number of ips are whitelisted
	if ($self->config->{'whitelist_ips'}) {
		foreach my $ip (@{$self->config->{'whitelist_ips'}}) {
			$self->whitelist_ips->{$ip} = 1;
		}
	}

	# load the firewall chain name
	if ($self->config->{'iptables_chain'}) {
		$self->iptables_chain($self->config->{'iptables_chain'});
	}

	# loop over all the log files
	if ($self->config->{'log_files'}) {
		my %rule_names;
		$self->log_files([]);

		foreach my $log_file_data (@{$self->config->{'log_files'}}) {
			die "No globname for: ".Dumper($log_file_data)    unless defined($log_file_data->{'globname'});
			die "No date_rule for: ".Dumper($log_file_data)   unless defined($log_file_data->{'date_rule'});
			die "Rules is not an array: ".Dumper($log_file_data) unless !defined($log_file_data->{'rules'}) || ref($log_file_data->{'rules'}) eq 'ARRAY';

			my @rules;
			my $this_file = {
				'globname' => $log_file_data->{'globname'},
				'colour'   => $log_file_data->{'colour'} || '',
				'rules'    => \@rules,
			};

			if ($log_file_data->{'rules'}) {
				foreach my $rule (@{$log_file_data->{'rules'}}) {
					die "No name for: ".Dumper($rule) unless defined($rule->{'name'});
					die "No type for: ".Dumper($rule) unless defined($rule->{'type'});
					die "Duplicate rule name '".$rule->{'name'}."'" if defined $rule_names{$rule->{'name'}};
					die "No rule for: ".Dumper($rule)
						unless (defined($rule->{'rule'}) || defined($rule->{'not_rule'}) || defined($rule->{'not_rule_nocase'}));

					$rule_names{$rule->{'name'}} = 1;
					$rule->{'colour'} ||= '';
					$rule->{'log_file'} = $this_file;

					# validate tail data
					if ($rule->{'type'} =~ /(^|\|)tail(\||$)/) {
						$rule->{'is_tail'} = 1;
					}

					# validate the ban data
					if ($rule->{'type'} =~ /(^|\|)ban(\||$)/) {
						$rule->{'is_ban'} = 1;
					}

					# quote the regex
					$rule->{'rule'} = qr/$rule->{'rule'}/ if defined $rule->{'rule'};
					$rule->{'not_rule_nocase'} = qr/$rule->{'not_rule_nocase'}/ if defined $rule->{'not_rule_nocase'};

					push @rules, $rule;
				}
			}

			# get the order of the variables
			my $date_rule = $log_file_data->{'date_rule'};
			my %order_sort;
			for my $var (@{$self->date_vars}) {
				my $offset = index($date_rule, '$'.$var);
				if ($offset > -1) {
					$order_sort{$offset} = $var;
				}
			}
			my @order = sort { int($a) <=> int($b) } keys(%order_sort);

			# get the final order
			my @date_order;
			my $index = 1;
			foreach my $offset (@order) {
				push @date_order, $order_sort{$offset};
			}
			$this_file->{'date_order'} = \@date_order;

			# create the date regex
			$date_rule =~ s/\$Y/(\\d{4})/;
			$date_rule =~ s/\$m/(\\d{1,2})/;
			$date_rule =~ s/\$M/(\\w{3})/;
			$date_rule =~ s/\$d/(\\d{1,2})/;
			$date_rule =~ s/\$h/(\\d{1,2})/;
			$date_rule =~ s/\$i/(\\d{1,2})/;
			$date_rule =~ s/\$s/(\\d{1,2})/;
			$this_file->{'date_rule'} = qr/$date_rule/;

			push @{$self->log_files}, $this_file;
			$self->date_rules->{qr/$date_rule/} = \@date_order;
		}
	}
}

sub get_all_log_files {
	my ($self, $type) = @_;

	my @log_files;
	$self->log_file_lookup({});
	my $log_file_index = 0;
	foreach my $log_file (@{$self->log_files}) {
		my @files;
		my $globname = $log_file->{'globname'};
		if ($globname =~ /\*/) {
			eval("\@files = <$globname>;");
		}
		else {
			@files = ($globname);
		}

		foreach my $file (@files) {
			$self->log_file_lookup->{$file} = $log_file_index;
		}

		push @log_files, @files;
		$log_file_index++;
	}

	return @log_files;
}

# Y - years   - 4 digits e.g. 2000
# M - months  - Jan through Dec
# m - months  - 01 - 12
# d - days    - (01 to 31) or (1 to 31)
# h - hours   - seconds - (00 to 23) or (0 to 23)
# i - minutes - (01 to 59) or (1 to 59)
# s - seconds - (01 to 59) or (1 to 59)
sub get_date_from_rule {
	my ($self, $message, $rule) = @_;

	my @date_parts = ($message =~ $rule->{'date_rule'});
	unless (@date_parts) {
		$self->logger->warn("Could not find date in line: ".$rule->{'date_rule'}." =~ $message");
		return undef;
	}
	my $string = $date_parts[0];

	my %date_vars = ('year' => (1900 +(localtime)[5]), 'time_zone' => 'floating');
	my $index = 1;
	for my $var (@{$rule->{'date_order'}}) {
		given ($var) {
			when (/^Y$/) {
				$date_vars{'year'} = $date_parts[$index];
			};
			when (/^m$/) {
				$date_vars{'month'} = $date_parts[$index]-1;
			};
			when (/^M$/) {
				$date_vars{'month'} = $months_abbrev{$date_parts[$index]}+1;
			};
			when (/^d$/) {
				$date_vars{'day'} = $date_parts[$index];
			};
			when (/^h$/) {
				$date_vars{'hour'} = $date_parts[$index];
			};
			when (/^i$/) {
				$date_vars{'minute'} = $date_parts[$index];
			};
			when (/^s$/) {
				$date_vars{'second'} = $date_parts[$index];
			};
		}
		$index++;
	}

	my $now  = time;
	my $date;
	eval {
		$date = timelocal($date_vars{'second'},$date_vars{'minute'},$date_vars{'hour'},$date_vars{'day'},$date_vars{'month'},$date_vars{'year'});
	};
	if ($@) {
		$self->logger->error("Could not parse date: $message\n".Dumper(\%date_vars)."\n".Dumper(\@date_parts)."\n".Dumper($rule->{'date_order'})) unless $self->test_log_file;
		return undef;
	}

	# adjust for if the new years passes
	if ($date > $now) {
		$date_vars{'year'}--;
	}

	$date = DateTime->new(%date_vars);

	return $date;
}

sub extract_date {
	my ($self, $line) = @_;

	if ($line =~ /^(.*?) : (.*)$/) {
		my $file       = $1;
		my $message    = $2;
		my $file_index = $logwatcher_object->log_file_lookup->{$file};
		my $log_file   = $logwatcher_object->log_files->[$file_index];

		if ($self->test_log_file) {
			foreach my $date_regex (keys %{$self->date_rules}) {
				my $date_rule = {
					'date_rule'  => $date_regex,
					'date_order' => $self->date_rules->{$date_regex},
				};
				my $date = $self->get_date_from_rule($message, $date_rule);
				return $date if $date;
			}
			return undef;
		}
		else {
			return $self->get_date_from_rule($message, $log_file);
		}
	}
}

sub test_rule {
	my ($self, $rule, $message) = @_;

	if (defined($rule->{'rule'}) && $message =~ qr/$rule->{'rule'}/) {
		return 1;
	}
	elsif (defined($rule->{'not_rule'}) && $message !~ qr/$rule->{'not_rule'}/) {
		return 1;
	}
	elsif (defined($rule->{'not_rule_nocase'}) && $message !~ qr/$rule->{'not_rule_nocase'}/i) {
		return 1;
	}

	return 0;
}

sub test_rules {
	my ($self, $file_index, $message) = @_;

	foreach my $rule (@{$self->log_files->[$file_index]->{'rules'}}) {
		if ($self->tail_mode && $rule->{'is_tail'}) {
			if ($self->test_rule($rule, $message)) {
				return $rule;
			}
		}
		elsif ($self->ban_mode && $rule->{'is_ban'}) {
			if ($self->test_rule($rule, $message)) {
				return $rule;
			}
		}
	}

	return undef;
}

sub _process_log_line {
	my $lines = shift;
	my @lines = @{$lines};

	if (scalar(@lines) == 0) {
		sleep 1;
	}

	if ($logwatcher_object->sort_lines || $logwatcher_object->sort_lines_once) {
		# reset sort_lines_once
		$logwatcher_object->sort_lines_once(0);

		# where the sorted lines will go
		my @new_lines;

		# loop over all the lines and extract the date
		foreach my $line (@lines) {
			my $date = $logwatcher_object->extract_date($line) or next;
			push @new_lines, {
				'line' => $line,
				'date' => $date,
			},
		}

		# sort the array
		@new_lines = sort {$a->{'date'} cmp $b->{'date'}} @new_lines;

		# recreate the lines array
		@lines = ();
		foreach my $line (@new_lines) {
			push @lines, $line->{'line'};
		}
	}

	foreach my $line (@lines) {
		next unless defined $line;
		$line =~ s/\n$//gs;
		next if $line =~ /^$/;
		if ($line =~ /^(.*?) : (.*)$/) {
			my $file       = $1;
			my $message    = $2;
			my $file_index = $logwatcher_object->log_file_lookup->{$file};

			my $rule = undef;
			if ($logwatcher_object->test_log_file) {
				for($file_index=0; $file_index<scalar(@{$logwatcher_object->log_files}); $file_index++) {
					$rule = $logwatcher_object->test_rules($file_index, $message);
					last if $rule;
				}
			}
			else {
				$rule = $logwatcher_object->test_rules($file_index, $message);
			}

			# colour codes http://en.wikipedia.org/wiki/ANSI_escape_code
			if ($rule) {
				if ($logwatcher_object->tail_mode && $rule->{'is_tail'}) {
					$logwatcher_object->do_tail($rule, $file, $message);
				}
				if ($logwatcher_object->ban_mode && $rule->{'is_ban'}) {
					$logwatcher_object->do_ban($rule, $file, $message);
				}
			}
		}
	}
}

sub tail_logs {
	my ($self) = @_;

	$self->load_state();
	$self->save_state();

	# create a list of files to tail
	my @log_files;
	if ($self->test_log_file) {
		@log_files = ( $self->test_log_file );
		$self->log_file_lookup->{$self->test_log_file} = 0;
		$self->last_run_file(undef);
	}
	else {
		@log_files = $self->get_all_log_files();
	}
	print "Tailing Log Files: ".Dumper(\@log_files);

	$logwatcher_object = $self;
	my $tail = File::Tail::Multi->new(
        'Function'        => \&_process_log_line,
		'RemoveDuplicate' => 0,
		'OutputPrefix'    => 'p',
		'NumLines'        => $self->num_tail_lines,
		'Files'           => \@log_files,
		'LastRun_File'    => $self->last_run_file,
		'ScanForFiles'    => 10,
	);

	if ($self->follow_tail) {
		while(1) {
			$self->state_changed(0);
			$self->last_just_banned($self->just_banned);
			$self->just_banned({});
			$tail->read;
			$self->do_unban();
			if ($self->state_changed) {
				$self->save_state();
			}
		}
	}
	else {
		$tail->read;
		$self->do_unban();
		$self->save_state();
	}
}

sub do_tail {
	my ($self, $rule, $file, $message) = @_;
	my $line = $file.' : '.$message;

	my $colour = $rule->{'colour'} || $rule->{'log_file'}->{'colour'} || '';
	$self->tail_print($colour, $line);
}

sub tail_print {
	my ($self, $colour, $line) = @_;

	if ($colour eq 'black') {
		print "\033[0;30m$line\033[0m\n";
	}
	elsif ($colour eq 'bold-black') {
		print "\033[1;30m$line\033[0m\n";
	}
	elsif ($colour eq 'red') {
		print "\033[0;31m$line\033[0m\n";
	}
	elsif ($colour eq 'bold-red') {
		print "\033[1;31m$line\033[0m\n";
	}
	elsif ($colour eq 'green') {
		print "\033[0;32m$line\033[0m\n";
	}
	elsif ($colour eq 'bold-green') {
		print "\033[1;32m$line\033[0m\n";
	}
	elsif ($colour eq 'yellow') {
		print "\033[0;33m$line\033[0m\n";
	}
	elsif ($colour eq 'bold-yellow') {
		print "\033[1;33m$line\033[0m\n";
	}
	elsif ($colour eq 'blue') {
		print "\033[0;34m$line\033[0m\n";
	}
	elsif ($colour eq 'bold-blue') {
		print "\033[1;34m$line\033[0m\n";
	}
	elsif ($colour eq 'magenta') {
		print "\033[0;35m$line\033[0m\n";
	}
	elsif ($colour eq 'bold-magenta') {
		print "\033[1;35m$line\033[0m\n";
	}
	elsif ($colour eq 'cyan') {
		print "\033[0;36m$line\033[0m\n";
	}
	elsif ($colour eq 'bold-cyan') {
		print "\033[1;36m$line\033[0m\n";
	}
	elsif ($colour eq 'white') {
		print "\033[0;37m$line\033[0m\n";
	}
	elsif ($colour eq 'bold-white') {
		print "\033[1;37m$line\033[0m\n";
	}
	else {
		print "$line\n" unless $logwatcher_object->only_coloured;
	}
}

sub do_ban {
	my ($self, $rule, $file, $message) = @_;
	my $line = $file.' : '.$message;

	# extract the data from the line
	my ($ip, $fragment);
	if ($message =~ qr/$rule->{'rule'}/) {
		my $first  = $1;
		my $second = $2;

		# get the data
		if ($rule->{'format'} eq "ip_message") {
			$ip       = $self->ip_to_int($first);
			$fragment = $second;
		}
		elsif ($rule->{'format'} eq "message_ip") {
			$fragment = $first;
			$ip       = $self->ip_to_int($second);
		}
		else {
			$self->logger->error("Incorrect Format: ".Dumper($rule));
		}
		my $name = $rule->{'name'};

		# get the date
		my $date = $self->get_date_from_rule($message, $rule->{'log_file'});
		unless (defined $date) {
			$self->logger->error("Could not extract date from: $line => ".Dumper($rule))
				unless $self->test_log_file;
			return;
		}
		$date = $date->ymd;

		# create a record in state for this event
		$self->state->{'ip_watch'}->{$date}->{$rule->{'name'}}->{$ip} = 0
			unless defined $self->state->{'ip_watch'}->{$date}->{$rule->{'name'}}->{$ip};
		$self->state->{'ip_watch'}->{$date}->{$rule->{'name'}}->{$ip}++;

		if ($self->state->{'ip_watch'}->{$date}->{$rule->{'name'}}->{$ip} >= $rule->{'threshold'}) {
			if ($self->iptables_ban($ip, $rule->{'name'})) {
				$self->state->{'ip_watch'}->{'banned'}->{$ip} = {
					'banned' => time(),
					'unban'  => time()+($rule->{'ban_time'} || 24*3600),
				};
				$self->logger->debug(Dumper($self->state->{'ip_watch'}->{'banned'}->{$ip}));
			}
		}

		$self->state_changed(1);
	}
}

sub do_unban {
	my ($self) = @_;

	my $time = time();
	foreach my $ip (keys %{$self->state->{'ip_watch'}->{'banned'}}) {
		if ($self->state->{'ip_watch'}->{'banned'}->{$ip}->{'unban'} < $time) {
			$self->iptables_unban($ip);
			delete $self->state->{'ip_watch'}->{'banned'}->{$ip};
			$self->state_changed(1);
		}
	}
}

sub run {
	my ($self) = @_;

	die "No mode specified." unless defined $self->mode;

	$self->logger->info("Starting LogWatcher Daemon ...");

	$self->load_config();

	given ($self->mode) {
		# when tail logs is set
		when (/^tail$/) {
			$self->tail_mode(1);
			$self->tail_logs();
		};

		# when tail logs is set
		when (/^ban$/) {
			$self->ban_mode(1);
			$self->tail_logs();
		};

		# when tail & ban logs is set
		when (/^tail-ban$/) {
			$self->tail_mode(1);
			$self->ban_mode(1);
			$self->tail_logs();
		};

		# default is to die
		default {
			die "'".$self->mode."' is not a valid mode."
		}
	}

}

after start => sub {
	my ($self) = @_;

	return unless $self->is_daemon;
	$self->run();
};

after stop => sub {
	my($self) = @_;
	$self->logger->info("Stopped LogWatcher Daemon");
};



#################################################################################
#################################################################################
#################################################################################
package Main;

use v5.14;
use Modern::Perl;

use Log::Log4perl qw(:levels);
use Log::Log4perl::CommandLine ':loginit' => [{
	'level' => $INFO,
	'file'  => '>>/var/log/logwatcher.log'
}];
use Getopt::Long;

# read the command line options
my $mode;
my $config_file;
my $state_file;
my $last_run_file;
my $num_tail_lines;
my $only_coloured;
my $follow_tail;
my $test_log_file;
my $sort_lines;
my $sort_lines_once;
GetOptions (
	"mode|m=s"           => \$mode,
	"config-file|c=s"    => \$config_file,
	"state-file|s=s"     => \$state_file,
	"last-run-file|l=s"  => \$last_run_file,
	"num-tail-lines|n=i" => \$num_tail_lines,
	"only-coloured|o"    => \$only_coloured,
	"follow_tail|f"      => \$follow_tail,
	"test-log-file=s"    => \$test_log_file,
	"sort"               => \$sort_lines,
	"sort-once"          => \$sort_lines_once,
) or die "Could not get command line options";

# create a logger
my $logger = Log::Log4perl->get_logger();

my %options = (
	'logger' => $logger
);
$options{'mode'}             = $mode               if defined $mode;
$options{'config_file'}      = $config_file        if defined $config_file;
$options{'state_file'}       = $state_file         if defined $state_file;
$options{'last_run_file'}    = $last_run_file      if defined $last_run_file;
$options{'num_tail_lines'}   = $num_tail_lines     if defined $num_tail_lines;
$options{'only_coloured'}    = $only_coloured      if defined $only_coloured;
$options{'follow_tail'}      = $follow_tail        if defined $follow_tail;
$options{'test_log_file'}    = $test_log_file      if defined $test_log_file;
$options{'sort_lines'}       = $sort_lines         if defined $sort_lines;
$options{'sort_lines_once'}  = $sort_lines_once    if defined $sort_lines_once;

# init the daemon
my $daemon = AKM::Logwatcher->new_with_options(
	'progname'             => 'LogWatcher',
	'dont_close_all_files' => 1,
	%options
);

if ($mode eq 'tail' || $mode eq 'tail-ban') {
	$daemon->run();
}
else {
	# look for a command
	my ($command) = @{$daemon->extra_argv};
	unless (defined ($command) &&
		($command eq 'start' || $command eq 'status' ||
		 $command eq 'restart' || $command eq 'stop')) {
		print "No command specified, must be either { start | status | restart | stop }\n";
		exit(-1);
	}

	# run in the foreground
	$daemon->logger->info('Running with command: ' . $command);
	if ($daemon->foreground) {
		$daemon->logger->info('Running in the foreground.');
	}

	$daemon->start   if $command eq 'start';
	$daemon->status  if $command eq 'status';
	$daemon->restart if $command eq 'restart';
	$daemon->stop    if $command eq 'stop';

	$daemon->logger->info($daemon->status_message || 'Unknown Status');
	print 'LogWatcher Daemon: ' . $daemon->status_message || 'Unknown Status';
	print "\n";
	exit($daemon->exit_code);
}
