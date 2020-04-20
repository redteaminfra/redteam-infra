#!/usr/bin/env ruby
require 'erb'

input = ARGV[0]
output = ARGV[1]

# FIXME: some input validation

class OCITemplate
  def options(input, protocol)
    min = nil
    max = nil
    if input.is_a? Integer
      min = input
      max = input
    end
    if input.is_a? String
      md = /(\d+)\s*-\s*(\d+)/.match(input)
      min = md[1]
      max = md[2]
    end
    if min and max
      return "    #{protocol}_options {\n" +
             "      min = #{min}\n" +
             "      max = #{max}\n" +
             "    }"
    else
      return ""
    end
  end

  def render(path)
    content = File.read(File.expand_path(path))
    t = ERB.new(content, nil, "<>")
    return t.result(binding)
  end
end

File.write(output, OCITemplate.new().render(input))
