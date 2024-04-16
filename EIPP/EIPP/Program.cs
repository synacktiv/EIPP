using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AzureAD.Policy.Password;

/*
namespace Microsoft.AzureAD.Policy.Password
{
    public enum BannedPasswordAlgorithm
	{
		None = 0,
		EditDistance = 1,
		Substring = 2,
		StrengthScore = 4,
		All = 7
	}

	public enum PasswordStatus
	{
		Valid,
		BannedByGlobalList,
		BannedByTenantList,
		BannedByAdditionalWords,
		BannedByGlobalAndTenantList
	}
}
*/

namespace EIPP
{
    class Program
    {
        public static int CustomBPLMaxLength = 1000;

        public static Guid tenantId = new Guid();
        public static string[] additionalBannedWords = { };
        public static BannedPasswordChecker bannedPasswordChecker;

        static int Main(string[] args)
        {
            if (args.Length >= 1)
            {
                if (args[0] == "normalize")
                    return Normalize(args);
                else if (args[0] == "stats")
                    return Stats(args);
                else if (args[0] == "generate")
                    return Generate(args);
            }

            Usage();
            return 1;
        }

        static void Usage()
        {
            Console.WriteLine($"usage:"
                + $"\n  {AppDomain.CurrentDomain.FriendlyName}.exe normalize passwords.txt"
                + $"\n  {AppDomain.CurrentDomain.FriendlyName}.exe generate [-t threads] [-m minOccurences] [-n entries] passwords.txt global.txt output.txt"
                + $"\n  {AppDomain.CurrentDomain.FriendlyName}.exe stats [-t threads] passwords.txt global.txt [tenant.txt]");
        }

        // Normalize a list of passwords (no sorting)
        static int Normalize(string[] args)
        {
            if (args.Length !=2)
            {
                Usage();
                return 1;
            }

            var passwords = File.ReadLines(args[1]);
            foreach (var password in passwords)
                Console.WriteLine(BannedPasswordHelper.NormalizeForBannedPassword(password));

            return 0;
        }

        // Return all substrings of input with length between minLength and maxLength
        static IEnumerable<string> Tokenize(string input, int minLength = 4, int maxLength = 16)
        {
            for (int i = 0; i < input.Length - minLength; i++)
            {
                for (int j = i + minLength; j <= Math.Min(input.Length, maxLength); j++)
                {
                    yield return input.Substring(i, j - i);
                }
            }
        }

        // Create workers and return threads
        static Task[] Enqueue(string[] passwords, BlockingCollection<Result> outQueue, string[] globalBannedPasswordList, string[] tenantBannedPasswordList = null, int numThreads = 4)
        {
            PasswordRuleSetting globalSetting = new PasswordRuleSetting(true, globalBannedPasswordList);
            PasswordRuleSetting tenantSetting = new PasswordRuleSetting(true, tenantBannedPasswordList);
            BannedPasswordDataProvider dataProvider = new BannedPasswordDataProvider(globalSetting, tenantSetting);
            bannedPasswordChecker = new BannedPasswordChecker(dataProvider);

            BlockingCollection<string> inQueue = new BlockingCollection<string>();
            Task[] threads = new Task[numThreads];
            for (int i = 0; i < threads.Length; i++)
                threads[i] = Task.Run(() => Worker(inQueue, outQueue));

            foreach (string password in passwords)
            {
                inQueue.Add(password);
            }
            inQueue.CompleteAdding();
            return threads;
        }

        // Generate an optimized custom BPL of max 1000 entries
        static int Generate(string[] args)
        {
            // Parsing [-t threads] [-m minOccurences] [-n entries]
            List<string> options = args.ToList();
            int optThreads = 4;
            int optMinOccurences = 5;
            int optNumEntries = CustomBPLMaxLength;
            int position = -1;

            position = options.IndexOf("-t");
            if (position != -1)
            {
                optThreads = int.Parse(options[position + 1]);
                options.RemoveAt(position);
                options.RemoveAt(position);
            }
            position = options.IndexOf("-m");
            if (position != -1)
            {
                optMinOccurences = int.Parse(options[position + 1]);
                options.RemoveAt(position);
                options.RemoveAt(position);
            }
            position = options.IndexOf("-n");
            if (position != -1)
            {
                optNumEntries = int.Parse(options[position + 1]);
                options.RemoveAt(position);
                options.RemoveAt(position);
            }

            if (options.Count != 4)
            {
                Usage();
                return 1;
            }
            
            int occurences, progress = 0;
            string[] passwords = (
                from entry in File.ReadLines(options[1]) select BannedPasswordHelper.NormalizeForBannedPassword(entry)).ToArray();
            string[] globalBannedPasswordList = (
                from entry in File.ReadLines(options[2]) select BannedPasswordHelper.NormalizeForBannedPassword(entry)).ToArray();
            string outFile = options[3];
            Dictionary<string, int> tokens = new Dictionary<string, int>();
            Dictionary<string, int> customBPL = new Dictionary<string, int>();


            // Normalize and tokenize passwords
            foreach (string password in passwords)
            {
                foreach (string token in Tokenize(BannedPasswordHelper.NormalizeForBannedPassword(password)))
                    tokens[token] = (tokens.TryGetValue(token, out occurences) ? occurences : 0) + 1;
            }

            // Select tokens found more than optMinOccurences
            string[] tenantBannedPasswordList = (from kv in tokens.Where(kv => kv.Value > optMinOccurences) select kv.Key).ToArray();
            BlockingCollection<Result> outQueue = new BlockingCollection<Result>();
            Task[] threads = Enqueue(passwords, outQueue, globalBannedPasswordList, tenantBannedPasswordList, optThreads);

            // Results worker
            Task counter = Task.Run(() =>
            {
                foreach (Result result in outQueue.GetConsumingEnumerable())
                {
                    progress += 1;
                    foreach (KeyValuePair<string, BannedPasswordSources> match in result.matchedBannedWords)
                    {
                        if (match.Value == BannedPasswordSources.Tenant)
                            customBPL[match.Key] = (customBPL.TryGetValue(match.Key, out occurences) ? occurences : 0) + 1;
                    }
                }
            });

            // Progress
            while (threads[0].Status == TaskStatus.Running)
            {
                Console.WriteLine($"Progress: {progress}/{passwords.Length} ({100 * progress / passwords.Length}%)");
                Thread.Sleep(30000);
            }

            Task.WaitAll(threads);
            outQueue.CompleteAdding();
            Task.WaitAll(counter);

            // Output
            using (StreamWriter writer = new StreamWriter(outFile))
            {
                foreach (var kv in customBPL.OrderByDescending(kv => kv.Value).Take(optNumEntries))
                    writer.WriteLine(kv.Key);
            }

            return 0;
        }

        // Calculate ban rate of a list of passwords given a global BPL and optional custom BPL
        static int Stats(string[] args)
        {
            // Parsing [-t threads]
            List<string> options = args.ToList();
            int optThreads = 4;
            int position = -1;

            position = options.IndexOf("-t");
            if (position != -1)
            {
                optThreads = int.Parse(options[position + 1]);
                options.RemoveAt(position);
                options.RemoveAt(position);
            }
            
            if (options.Count < 3 || options.Count > 4)
            {
                Usage();
                return 1;
            }

            int banned = 0;
            string[] passwords = File.ReadAllLines(options[1]);
            string[] globalBannedPasswordList = (
                from entry in File.ReadLines(options[2]) select BannedPasswordHelper.NormalizeForBannedPassword(entry)).ToArray();
            string[] tenantBannedPasswordList = { };
            if (args.Length == 4)
                tenantBannedPasswordList = (
                from entry in File.ReadLines(options[3]) select BannedPasswordHelper.NormalizeForBannedPassword(entry)).ToArray();

            BlockingCollection<Result> outQueue = new BlockingCollection<Result>();
            Task[] threads = Enqueue(passwords, outQueue, globalBannedPasswordList, tenantBannedPasswordList, optThreads);

            // Logger worker
            Task logger = Task.Run(() =>
            {
                foreach (Result result in outQueue.GetConsumingEnumerable())
                {
                    if (result.passwordStatus != PasswordStatus.Valid)
                        banned += 1;
                    Console.WriteLine($"{result.passwordStatus},{result.matchAlgorithm},{result.password},{result.normalizedPassword}");
                }
            });

            Task.WaitAll(threads);
            outQueue.CompleteAdding();
            Task.WaitAll(logger);

            // Output rate
            Console.WriteLine($"Result: {100 * banned / passwords.Length}% banned");
            return 0;
        }

        // Results of BannedPasswordChecker.CheckPassword()
        public class Result
        {
            public PasswordStatus passwordStatus;
            public BannedPasswordAlgorithm matchAlgorithm;
            public string password;
            public string normalizedPassword;
            public IDictionary<string, BannedPasswordSources> matchedBannedWords;
        }

        // Worker calling BannedPasswordChecker.CheckPassword()
        static void Worker(BlockingCollection<string> inQueue, BlockingCollection<Result> outQueue)
        {
            PasswordStatus passwordStatus;
            IDictionary<string, BannedPasswordSources> matchedBannedWords;
            BannedPasswordAlgorithm matchAlgorithm;
            foreach (string password in inQueue.GetConsumingEnumerable())
            {
                string normalizedPassword = BannedPasswordHelper.NormalizeForBannedPassword(password);
                passwordStatus = bannedPasswordChecker.CheckPassword(tenantId, password, additionalBannedWords, out matchedBannedWords, out matchAlgorithm);

                outQueue.Add(new Result
                {
                    passwordStatus = passwordStatus,
                    matchAlgorithm = matchAlgorithm,
                    password = password,
                    normalizedPassword = normalizedPassword,
                    matchedBannedWords = matchedBannedWords
                });
            }
        }
    }

    class BannedPasswordDataProvider : IBannedPasswordDataProvider
    {
        private PasswordRuleSetting globalPasswordRuleSetting;
        private PasswordRuleSetting tenantPasswordRuleSetting;

        public BannedPasswordDataProvider(PasswordRuleSetting globalPasswordRuleSetting, PasswordRuleSetting tenantPasswordRuleSetting = null)
        {
            this.globalPasswordRuleSetting = globalPasswordRuleSetting;
            this.tenantPasswordRuleSetting = tenantPasswordRuleSetting;
        }

        public BannedPasswordData GlobalData
        {
            get
            {
                return new BannedPasswordData(DateTime.UtcNow, this.globalPasswordRuleSetting, TimeSpan.Zero);
            }
        }

        public BannedPasswordData GetGlobalAndTenantData(Guid tenantId)
        {
            return new BannedPasswordData(DateTime.UtcNow, this.globalPasswordRuleSetting, this.tenantPasswordRuleSetting, TimeSpan.Zero);
        }
    }
}