global ipTable :table[addr] of set[string] = table();

event http_reply(c: connection, version: string, code: count, reason: string)
	{
		local temp :set[string] = set();
		local ipaddress :addr= c$id$orig_h;
		local useragent :string = c$http$user_agent;
		if(ipaddress in ipTable)
		{
			if(useragent in ipTable[ipaddress])
			{}
			else
			{
				add ipTable[ipaddress][useragent];
			}
		}else
		{
			ipTable[ipaddress] = temp;
			add ipTable[ipaddress][useragent];
		}
	}
	
event zeek_init()
	{
	}

event zeek_done()
	{
	local c : int= 0;
	local t = "";
	for(key in ipTable)
	{
		c = 0;
		for(s in ipTable[key])
		{
			c = c + 1;
		}
		if(c > 2)
		{	
			print fmt("%s is a proxy", key);
		}
	}
	}