local datetime = require "datetime"
local nmap = require "nmap"
local outlib = require "outlib"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"
local unicode = require "unicode"
local have_openssl, openssl = pcall(require, "openssl")


description = [[
Retrieves a server's SSL certificate chain. It inspects the validity of the signed
certificates, some certificate fields and compares the server names against a
user-defined blacklist.
]]


author = "Hugo Delgado"


categories = { "default", "safe", "discovery" }
dependencies = {"https-redirect"}


portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end


--Args
local args = nmap.registry.args
local blacklist

if args["list"] then
	blacklist = args["list"]
else
	blacklist = "blacklist.csv"
end



-- Find the index of a value in an array.
function table_find(t, value)
  local i, v
  for i, v in ipairs(t) do
    if v == value then
      return i
    end
  end
  return nil
end

function date_to_string(date)
  if not date then
    return "MISSING"
  end
  if type(date) == "string" then
    return string.format("Can't parse; string is \"%s\"", date)
  else
    return datetime.format_timestamp(date)
  end
end

-- These are the subject/issuer name fields that will be shown, in this order,
-- without a high verbosity.
local NON_VERBOSE_FIELDS = { "commonName", "organizationName",
"stateOrProvinceName", "countryName" }

-- Test to see if the string is UTF-16 and transcode it if possible
local function maybe_decode(str)
  -- If length is not even, then return as-is
  if #str < 2 or #str % 2 == 1 then
    return str
  end
  if str:byte(1) > 0 and str:byte(2) == 0 then
    -- little-endian UTF-16
    return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, false, nil)
  elseif str:byte(1) == 0 and str:byte(2) > 0 then
    -- big-endian UTF-16
    return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, true, nil)
  else
    return str
  end
end

function stringify_name(name)
  local fields = {}
  local _, k, v
  if not name then
    return nil
  end
  for _, k in ipairs(NON_VERBOSE_FIELDS) do
    v = name[k]
    if v then
      fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
    end
  end
  if nmap.verbosity() > 1 then
    for k, v in pairs(name) do
      -- Don't include a field twice.
      if not table_find(NON_VERBOSE_FIELDS, k) then
        if type(k) == "table" then
          k = table.concat(k, ".")
        end
        fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
      end
    end
  end
  return table.concat(fields, "/")
end


local function isBlacklisted(name, blacklist)
  for _, entry in ipairs(blacklist) do
    local parts = {}
    for part in entry:gmatch("[^;]+") do
      table.insert(parts, part)
    end
    local dateReported, namePattern, severity = parts[1], parts[2], parts[3]
    
    if name == namePattern then
      return true, dateReported, severity
    end
  end
  return false
end


local function readCSVFile(filename)
  local contents = {}
  local file = assert(io.open(filename, "r"))
  for line in file:lines() do
    table.insert(contents, line)
  end
  
  file:close()
  return contents
end

local function get_cert_chain(host, port)
  local cmd = string.format("echo | openssl s_client -connect %s:%d -showcerts", host.ip, port.number)
  local handle = io.popen(cmd)
  local output = handle:read("*a")
  handle:close()
  return output
end

local function check_issuer(host, port)
  local output = get_cert_chain(host,port)

  if output and output ~= "" then
    local certificate_chain = {}
    local current_cert = {}
    for line in output:gmatch("([^\n]*)\n") do
      if line:match("^ %d s:") or line:match("   i:") then
	 table.insert(current_cert, string.sub(line,5))
      end
    end

    if current_cert[2] == current_cert[3] then
      return true
    end
  end
  return false
end
 

local function check_sign(host, port)
  local output = get_cert_chain(host,port)
  local lines = {}

  local i=1
  for line in output:gmatch("-----BEGIN CERTIFICATE-----%s(.-)-----END CERTIFICATE-----") do
    line = "-----BEGIN CERTIFICATE-----\n" .. line .. "-----END CERTIFICATE-----"
    local name = "cert" .. i .. ".pem"
    local file = io.open(name, "w")
    file:write(line)
    file:close()
    
    i = i+1
  end
  
  local cmd = "openssl verify -verbose -CAfile cert2.pem cert1.pem"
  local handle = io.popen(cmd)
  local check = handle:read("*a")
  handle:close()
  if string.find(check,"OK") then
    return true
  else
    return false
  end 
end


function extractDomain(inputString, delimiter)
    local result = {}
    for match in (inputString..delimiter):gmatch("DNS:(.-)"..delimiter) do
        table.insert(result, match)
    end
    return result
end


function extractDomainName(inputString)
    local pattern = "([%w-]+%.[%w-]+)$"
    local match = inputString:match(pattern)
    return match
end

function checkValidity(startDate,endDate)
  local start = startDate.year * 365 + startDate.month * 30 + startDate.day 
  local finish = endDate.year * 365 + endDate.month * 30 + endDate.day
  local duration = finish - start
  return duration     
end


function checkAlgorithm(algorithm)
  local cipher = false
  local hash = false
  if (string.match(algorithm, "RSA")) then 
    cipher = true
  elseif (string.match(algorithm, "ECDSA")) then
    cipher = true
  elseif (string.match(algorithm, "DSA")) then
    cipher = true  
  else
    cipher = false
  end
  
  if(string.match(algorithm,"sha")) then
    local patron = "sha(%d+)"
    local numero = algorithm:match(patron)
    if (tonumber(numero) >= 256) then
      hash = true
    else
      hash = false
    end
  else
    hash = false
  end
    
  return cipher, hash
end


local function output_str(cert, host, port)
  if not have_openssl then
    -- OpenSSL is required to parse the cert, so just dump the PEM
    return "OpenSSL required to parse certificate.\n" .. cert.pem
  end
  local lines = {}
  
  lines[#lines + 1] = "X509certs Script"
  

  lines[#lines + 1] = "----Authenticity and issuance by CA----"
 
  if check_issuer(host, port) then
    lines[#lines + 1] = "Issuer and subject match correctly"
  else
    lines[#lines + 1] = "Certificate not correct: Issuer and subject do not match"
  end
  
  if check_sign(host, port) then
    lines[#lines + 1] = "Server certificate signed by CA"
  else
    lines[#lines + 1] = "Server certificate not signed by CA (not valid)"
  end
  
 -- Check validity
  lines[#lines + 1] = "----Validity----"
  local currentDay = os.date("%Y-%m-%dT%H:%M:%S")
  if currentDay > date_to_string(cert.validity.notBefore) and currentDay < date_to_string(cert.validity.notAfter) then
    lines[#lines + 1] = "Valid certificate date"
  else
    lines[#lines + 1] = "Not valid certificate date"
  end

  local blackContents = readCSVFile("blacklist.csv")
  
  -- Check blacklist  
  local subjectMatch, dateReported, severitySubject = isBlacklisted(cert.subject.commonName, blackContents)
  local subjectMatch2, dateReported2, severitySubject2 = isBlacklisted(cert.subject.organizationName, blackContents)
  local issuerMatch, dateReportedIssuer, severityIssuer = isBlacklisted(cert.issuer.commonName, blackContents)
  local issuerMatch2, dateReportedIssuer2, severityIssuer2 = isBlacklisted(cert.issuer.organizationName, blackContents)
  lines[#lines + 1] = "----Organization Search----"
  if subjectMatch then
    lines[#lines + 1] = "->" .. cert.subject.commonName .. " found in blacklist. Severity: "  .. severitySubject .. ", Date: " .. dateReported
  end
  if subjectMatch2 then
    lines[#lines + 1] = "->" .. cert.subject.organizationName .. " found in blacklist. Severity: "  .. severitySubject2 .. ", Date: " .. dateReported2
  end
  if issuerMatch then
     lines[#lines + 1] = "->" .. cert.issuer.commonName .. " found in blacklist. Severity: "  .. severityIssuer .. ", Date: " .. dateReportedIssuer
  end
  if issuerMatch2 then
     lines[#lines + 1] = "->" .. cert.issuer.organizationName .. " found in blacklist. Severity: "  .. severityIssuer2 .. ", Date: " .. dateReportedIssuer2
  end
  

 -- Check Alternative Name
    lines[#lines + 1] = "----Alternative Names----"
   if cert.extensions then
    for _, e in ipairs(cert.extensions) do
      if e.name == "X509v3 Subject Alternative Name" then
         local domainTable = extractDomain(e.value, ", ")
         if cert.subject.commonName then
          local cn = false
          for _, domainName in ipairs(domainTable) do
            if extractDomainName(domainName) ~= extractDomainName(cert.subject.commonName) then
              lines[#lines + 1] = "The Alternative Name " .. domainName .. " does not contain the domain name of the server " .. extractDomainName(cert.subject.commonName)
            end
            local match, date, severity = isBlacklisted(domainName, blackContents)
            if match then
              lines[#lines + 1] = "->" ..  domainName .. " found in blacklist. Severity: " .. severity .. ", Date: " .. date
            end
            if domainName == cert.subject.commonName then
              cn = true
            end
          end      
          if cn == false then
            lines[#lines + 1] = "The Common Name " .. cert.subject.commonName .. " does NOT match any Alternative Names"
          -- else
            -- lines[#lines + 1] = "No issues found"
          end
         end
        break
      end
    end
  end
  
  if cert.issuer.commonName and cert.subject.commonName then
    lines[#lines + 1] = "----Self-Signed Certificate----"
    if cert.issuer.commonName == cert.subject.commonName then
      lines[#lines + 1] = "True"
    else
      lines[#lines + 1] = "False"
    end
  end
  
  lines[#lines + 1] = "----Validity Period----"
  local month = 30
  local year = 365
  local duration = checkValidity(cert.validity.notBefore,cert.validity.notAfter)
  lines[#lines + 1] = "Validity: " .. duration .. " days"
  lines[#lines + 1] = "Not valid before: " ..  date_to_string(cert.validity.notBefore)
  lines[#lines + 1] = "Not valid after:  " ..  date_to_string(cert.validity.notAfter)
  
  if (duration <= month) then
    lines[#lines + 1] = "Warning: Validity period is too short (less than a month)."
  elseif (duration >= (2*year)) then
    lines[#lines + 1] = "Warning: Validity period is too long (more than two years)."
  else
    lines[#lines + 1] = "Validity period is correct."
  end
  
  lines[#lines + 1] = "----Public Key Length----"
  --lines[#lines + 1] = "Public Key bits: " .. cert.pubkey.bits
  if (cert.pubkey.bits < 2048) then
    lines[#lines + 1] = "Warning: The public key is too short: " .. cert.pubkey.bits .. " bit"
  else
    lines[#lines + 1] = "The public key length is correct."
  end
  
  lines[#lines + 1] = "----Signature Algorithm----"
  --lines[#lines + 1] = "Signature Algorithm: " .. cert.sig_algorithm
  local cipher,hash = checkAlgorithm(cert.sig_algorithm)
  if (cipher) and (hash) then
    lines[#lines + 1] = "Algorithm signature is correct: " .. cert.sig_algorithm
  else
    lines[#lines + 1] = "Warning: Algorithm signature is weak: " .. cert.sig_algorithm
  end
   
  return table.concat(lines, "\n")
end




action = function(host, port)
  host.targetname = tls.servername(host)
  local status, cert = sslcert.getCertificate(host, port)
  
  if ( not(status) ) then
    stdnse.debug1("getCertificate error: %s", cert or "unknown")
    return
  end 
  

  return output_str(cert, host, port)
end


