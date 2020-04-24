using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

using System.Net.Http;
using System.Net.Http.Headers;

using Kerberos.NET;
using Kerberos.NET.Asn1;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;

namespace RestNegotiateClient
{
    class Program
    {
        static ILogger logger;
	static ILoggerFactory loggerFactory;
        static async Task Main(string[] args)
        {
            loggerFactory = LoggerFactory.Create(builder =>
            {
                builder
                    .AddFilter("Microsoft", LogLevel.Warning)
                    .AddFilter("System", LogLevel.Warning)
                    .AddFilter("RestNegotiateClient.Program", LogLevel.Debug)
                    .AddFilter("Kerberos.Net", LogLevel.Trace)
		    .AddConsole(delegate(ConsoleLoggerOptions d) {  });
            });
            logger = loggerFactory.CreateLogger<Program>();
            /*CommandLineArguments parsedArgs = new CommandLineArguments(args);
            String url = (String) parsedArgs.GetValueOrDefault("");
            if (!parsedArgs.ContainsKey("keytab")) {
                await Console.Error.WriteLineAsync("Syntax: RestNegotiateClient --keytab <keytab> --principal <principal> <url>");
                return;
            }
            String keytab = (String) parsedArgs.GetValueOrDefault("keytab", "krb5.keytab");
            String principal = (String) parsedArgs.GetValueOrDefault("principal", "cud/hostname.it.ox.ac.uk@OX.AC.UK");*/
            String keytab = args[0];
            String principal = args[1];
            String url = args[2];
            String outfile = args[3];
            Console.Error.WriteLine("keytab={0}, principal={1}, url={2}", keytab, principal, url, outfile);

            Uri uri = null;
            if (!Uri.TryCreate(url, UriKind.Absolute, out uri)) {
                throw new ArgumentException(String.Format("Invalid URL: {0}", url));
            }
            String serverPrincipal = String.Format("HTTP/", uri.Host);

            IKerberosTransport[] transports = {new UdpKerberosTransport("kdc0.ox.ac.uk")};
            transports[0].Enabled = true;
            var client = new KerberosClient(loggerFactory, transports);
            var keyTable = new KeyTable(File.ReadAllBytes(keytab));
            var kerbCred = new KeytabCredential(principal, keyTable, "OX.AC.UK");
            Console.WriteLine("User name: {0}", kerbCred.UserName);
            await client.Authenticate(kerbCred);
            Console.WriteLine("Authenticated!");
            /*
            var ticketRequest = new RequestServiceTicket();
            ticketRequest.ServicePrincipalName = KrbPrincipalName.FromString("HTTP/" + uri.DnsSafeHost, PrincipalNameType.NT_PRINCIPAL, "OX.AC.UK").ToString();
            ticketRequest.ApOptions |= ApOptions.MutualRequired;
            ticketRequest.Realm = "OX.AC.UK";
            */
            var ticket = await client.GetServiceTicket("HTTP/" + uri.DnsSafeHost + "@OX.AC.UK");
            String spnego = Convert.ToBase64String(ticket.EncodeGssApi().ToArray());
            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Negotiate", spnego);
            using (var outStream = File.Open(outfile, FileMode.Create)) {
                var httpStream = await httpClient.GetStreamAsync(uri);
                await httpStream.CopyToAsync(outStream);
            }
        }
    }
}
