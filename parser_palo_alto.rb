require 'fluent/parser'

module Fluent
  class TextParser
    class FirewallParser_pan < Parser
      # Register this parser as "firewall"
      Fluent::Plugin.register_parser("palo_alto", self)
      
      config_param :time_format, :string, default: "%b %e %H:%M:%S"

      def initialize()
        super

        @time = '\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
        @ipv6 = '((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?'
        @ipv4 = '(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])'
        @ip = "(?:#@ipv4|#@ipv6@)"
        @hostname = '\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)'
        @iporhost = "(?:#@ip|#@hostname)"

        # PAN 7.1.* Traffic Log - https://www.paloaltonetworks.com/documentation/71/pan-os/pan-os/monitoring/syslog-field-descriptions
        @r1 = /^(?<time>#@time) (?<dvchost>#@iporhost) (?<f1>\d+),(?<recvTime>.*?),(?<serialNum>\d+),(?<type>TRAFFIC),(?<subtype>\w+),(?<f2>\d+),(?<genTime>.*?),(?<src_ip>[.\d]+),(?<dest_ip>[.\d]+),(?<natsrc_ip>[.\d]+),(?<natdest_ip>[.\d]+),(?<ruleName>.*?),(?<src_user>.*?),(?<dest_user>.*?),(?<app>.*?),(?<vsys>.*?),(?<src_zone>.*?),(?<dest_zone>.*?),(?<ingress_if>.*?),(?<egress_if>.*?),(?<logProfile>.*?),(?<f3>.*?),(?<sessionID>.*?),(?<repeatCnt>.*?),(?<src_port>.*?),(?<dest_port>.*?),(?<natsrc_port>.*?),(?<natdest_port>.*?),(?<flags>.*?),(?<protocol>.*?),(?<action>.*?),(?<bytes>.*?),(?<bytes_sent>.*?),(?<bytes_recv>.*?),(?<packets>.*?),(?<start_time>.*?),(?<elapsed_time>.*?),(?<cat>.*?),(?<f4>.*?),(?<seqNum>.*?),(?<action_flags>.*?),(?<src_loc>.*?),(?<dest_loc>.*?),(?<f5>.*?),(?<packets_sent>.*?),(?<packets_rcv>.*?),(?<session_end_reason>.*?),(?<dev_group_hierarchy_1>.*?),(?<dev_group_hierarchy_2>.*?),(?<dev_group_hierarchy_3>.*?),(?<dev_group_hierarchy_4>.*?),(?<vsys_name>.*?),(?<dev_name>.*?),(?<action_source>.*?).*$/
        # PAN 7.1.* Threat Log - https://www.paloaltonetworks.com/documentation/71/pan-os/pan-os/monitoring/syslog-field-descriptions
        @r2 = /^(?<time>#@time) (?<dvchost>#@iporhost) (?<f1>\d+),(?<recvTime>.*?),(?<serialNum>\d+),(?<type>THREAT),(?<subtype>\S+),(?<f2>\d+),(?<genTime>.*?),(?<src_ip>[.\d]+),(?<dest_ip>[.\d]+),(?<natsrc_ip>[.\d]+),(?<natdest_ip>[.\d]+),(?<ruleName>.*?),(?<src_user>.*?),(?<dest_user>.*?),(?<app>.*?),(?<vsys>.*?),(?<src_zone>.*?),(?<dest_zone>.*?),(?<ingress_if>.*?),(?<egress_if>.*?),(?<logProfile>.*?),(?<f3>.*?),(?<sessionID>.*?),(?<repeatCnt>.*?),(?<src_port>.*?),(?<dest_port>.*?),(?<natsrc_port>.*?),(?<natdest_port>.*?),(?<flags>.*?),(?<protocol>.*?),(?<action>.*?),(?<misc>.*?),(?<threatID>.*?),(?<cat>.*?),(?<severity>.*?),(?<direction>.*?),(?<seqNum>.*?),(?<action_flags>.*?),(?<src_loc>.*?),(?<dest_loc>.*?),(?<f4>.*?),(?<content_type>.*?),(?<pcap_id>.*?),(?<filedigest>.*?),(?<cloud>.*?),(?<url_index>.*?),(?<user_agent>.*?),(?<file_type>.*?),(?<x_forwarded_for>.*?),(?<referer>.*?),(?<sender>.*?),(?<subject>.*?),(?<recipient>.*?),(?<report_id>.*?),(?<dev_group_hierarchy_1>.*?),(?<dev_group_hierarchy_2>.*?),(?<dev_group_hierarchy_3>.*?),(?<dev_group_hierarchy_4>.*?),(?<vsys_name>.*?),(?<dev_name>.*?),(?<f5>.*?).*$/
        # PAN 7.1.* System Log - https://www.paloaltonetworks.com/documentation/71/pan-os/pan-os/monitoring/syslog-field-descriptions
        @r3 = /^(?<time>#@time) (?<dvchost>#@iporhost) (?<f1>\d+),(?<recvTime>.*?),(?<serialNum>\d+),(?<type>SYSTEM),(?<subtype>.*?),(?<f2>\d+),(?<genTime>.*?),(?<vsys>.*?),(?<event_id>.*?),(?<object>.*?),(?<f3>.*?),(?<f4>.*?),(?<module>.*?),(?<severity>.*?),(?<description>.*?),(?<seqNum>.*?),(?<action_flags>.*?),(?<dev_group_hierarchy_1>.*?),(?<dev_group_hierarchy_2>.*?),(?<dev_group_hierarchy_3>.*?),(?<dev_group_hierarchy_4>.*?),(?<vsys_name>.*?),(?<dev_name>.*?).*$/
        # PAN 7.1.* Hip Log - https://www.paloaltonetworks.com/documentation/71/pan-os/pan-os/monitoring/syslog-field-descriptions
        @r4 = /^(?<time>#@time) (?<dvchost>#@iporhost) (?<f1>\d+),(?<recvTime>.*?),(?<serialNum>\d+),(?<type>HIP.*?),(?<subtype>\S+),(?<f2>\d+),(?<genTime>.*?),(?<src_user>.*?),(?<vsys>.*?),(?<machine_name>.*?),(?<os>.*?),(?<src_ip>.*?),(?<hip>.*?),(?<repeatCnt>.*?),(?<hip_type>.*?),(?<f3>.*?),(?<f4>.*?),(?<seqNum>.*?),(?<action_flags>.*?),(?<dev_group_hierarchy_1>.*?),(?<dev_group_hierarchy_2>.*?),(?<dev_group_hierarchy_3>.*?),(?<dev_group_hierarchy_4>.*?),(?<vsys_name>.*?),(?<dev_name>.*?).+$/
        # PAN 7.1.* Config Log - https://www.paloaltonetworks.com/documentation/71/pan-os/pan-os/monitoring/syslog-field-descriptions
        @r5 = /^(?<time>#@time) (?<dvchost>#@iporhost) (?<f1>\d+),(?<recvTime>.*?),(?<serialNum>\d+),(?<type>CONFIG.*?),(?<subtype>\S+),(?<f2>\d+),(?<genTime>.*?),(?<src_ip>.*?),(?<vsys>.*?),(?<command>.*?),(?<admin>.*?),(?<client>.*?),(?<result>.*?),(?<config_path>.*?),(?<seqNum>.*?),(?<action_flags>.*?),(?<before_change_detail>.*?),(?<after_change_detail>.*?),(?<dev_group_hierarchy_1>.*?),(?<dev_group_hierarchy_2>.*?),(?<dev_group_hierarchy_3>.*?),(?<dev_group_hierarchy_4>.*?),(?<vsys_name>.*?),(?<dev_name>.*?).*$/
      
        @asa_regex = Regexp.union(@r1, @r2, @r3, @r4, @r5)
      end

      # This method is called after config_params have read configuration parameters
      def configure(conf)
        super

        # TimeParser class is already given. It takes a single argument as the time format
        # to parse the time string with.
        @time_parser = TimeParser.new(@time_format)
      end

      # This is the main method. The input "text" is the unit of data to be parsed.
      # If this is the in_tail plugin, it would be a line. If this is for in_syslog,
      # it is a single syslog message.
      def parse(text)

        unless m = @asa_regex.match(text)
          yield nil, nil
        else
          record = {}
          time = @time_parser.parse(m['time'])

          m.names.each do |name|
            record[name] = m[name] if m[name]
          end

          yield time, record
        end
      end
    end
  end
end
