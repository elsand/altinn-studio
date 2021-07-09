using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Altinn.Authorization.ABAC.Constants;
using Altinn.Authorization.ABAC.Interface;
using Altinn.Authorization.ABAC.UnitTest.Utils;
using Altinn.Authorization.ABAC.Xacml;

using Moq;

using Xunit;
using Xunit.Abstractions;

namespace Altinn.Authorization.ABAC.UnitTest
{
    public class AltinnAppsTests
    {
        ITestOutputHelper _output;

        public AltinnAppsTests(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public void PDP_AuthorizeAccess_AltinnApps0001()
        {
            bool contextRequstIsEnriched = true;
            string testCase = "AltinnApps0001";

            XacmlContextResponse contextResponeExpected = XacmlTestDataParser.ParseResponse(testCase + "Response.xml", GetAltinnAppsPath());
            XacmlContextResponse xacmlResponse = SetuUpPolicyDecisionPoint(testCase, contextRequstIsEnriched);

            AssertionUtil.AssertEqual(contextResponeExpected, xacmlResponse);
        }

        [Fact]
        public void PDP_AuthorizeAccess_AltinnApps0002()
        {
            bool contextRequstIsEnriched = true;
            string testCase = "AltinnApps0002";

            XacmlContextResponse contextResponeExpected = XacmlTestDataParser.ParseResponse(testCase + "Response.xml", GetAltinnAppsPath());
            XacmlContextResponse xacmlResponse = SetuUpPolicyDecisionPoint(testCase, contextRequstIsEnriched);

            AssertionUtil.AssertEqual(contextResponeExpected, xacmlResponse);
        }

        [Fact]
        public void PDP_AuthorizeAccess_AltinnApps0003()
        {
            bool contextRequstIsEnriched = true;
            string testCase = "AltinnApps0003";

            XacmlContextResponse contextResponeExpected = XacmlTestDataParser.ParseResponse(testCase + "Response.xml", GetAltinnAppsPath());
            XacmlContextResponse xacmlResponse = SetuUpPolicyDecisionPoint(testCase, contextRequstIsEnriched);

            AssertionUtil.AssertEqual(contextResponeExpected, xacmlResponse);
        }

        [Fact]
        public void Test_get_all_delegable_actions()
        {
            var outer_sw = new Stopwatch();
            var sw = new Stopwatch();
            float elapsedMs;
            outer_sw.Start();
            sw.Start();

            string testCase = "AltinnApps9999";
            XacmlPolicy policy = XacmlTestDataParser.ParsePolicy(testCase + "Policy.xml", GetAltinnAppsPath());
            sw.Stop();
            elapsedMs = sw.ElapsedTicks / (float)Stopwatch.Frequency * 1000;
            _output.WriteLine("Parsing policy: {0:F3} ms", elapsedMs);

            sw.Restart();
            // Find all actions defined in the policy
            var actionCategory = new Uri(XacmlConstants.MatchAttributeCategory.Action);
            var actions = (
                    from rule in policy.Rules
                    from anyOf in rule.Target.AnyOf
                    from allOf in anyOf.AllOf
                    from match in allOf.Matches
                    where match.AttributeDesignator.Category.Equals(actionCategory)
                    select match.AttributeValue.Value).Distinct();

            sw.Stop();
            elapsedMs = sw.ElapsedTicks / (float)Stopwatch.Frequency * 1000;
            _output.WriteLine("Getting all actions: {0:F3} ms", elapsedMs);

            sw.Restart();
            // Find all tasks defined in the policy
            var tasks = (
                from rule in policy.Rules
                from anyOf in rule.Target.AnyOf
                from allOf in anyOf.AllOf
                from match in allOf.Matches
                where match.AttributeDesignator.AttributeId.Equals("urn:altinn:task")
                select match.AttributeValue.Value).Distinct();

            sw.Stop();
            elapsedMs = sw.ElapsedTicks / (float)Stopwatch.Frequency * 1000;
            _output.WriteLine("Getting all tasks: {0:F3} ms", elapsedMs);
            // Build a request
            XacmlContextRequest contextRequestEnriched = XacmlTestDataParser.ParseRequest(testCase + "Request_Enriched.xml", GetAltinnAppsPath());

            // Mock context handler, we are already enriched
            Moq.Mock<IContextHandler> moqContextHandler = new Mock<IContextHandler>();
            moqContextHandler.Setup(c => c.Enrich(It.IsAny<XacmlContextRequest>())).ReturnsAsync(contextRequestEnriched);

            PolicyDecisionPoint pdp = new PolicyDecisionPoint();

            // simple result for debugging
            Collection<string> results = new Collection<string>();

            int numberOfPDPCalls = 0;
            int reps = 1;
            sw.Start();
            for (var i = 0; i < reps; i++)
            {
                // Iterate all action without task
                foreach (var action in actions)
                {
                    SetContextRequestAction(contextRequestEnriched, action);
                    XacmlContextResponse xacmlResponse = pdp.Authorize(contextRequestEnriched, policy);
                    numberOfPDPCalls++;
                    if (xacmlResponse.Results.First().Decision == XacmlContextDecision.Permit)
                    {
                        results.Add("Can '" + action + "' on app itself");
                    }
                }

                // Iterate over all tasks for all actions
                foreach (var task in tasks)
                {
                    SetContextRequestTask(contextRequestEnriched, task);

                    foreach (var action in actions)
                    {
                        SetContextRequestAction(contextRequestEnriched, action);

                        XacmlContextResponse xacmlResponse = pdp.Authorize(contextRequestEnriched, policy);
                        numberOfPDPCalls++;
                        if (xacmlResponse.Results.First().Decision == XacmlContextDecision.Permit)
                        {
                            results.Add("Can '" + action + "' on task '" + task + "'");
                        }
                    }
                }
            }

            sw.Stop();
            outer_sw.Stop();

            

            float perCall = sw.ElapsedMilliseconds / numberOfPDPCalls;
            _output.WriteLine("Reps       : {0}", reps);
            _output.WriteLine("PDP calls  : {0}", numberOfPDPCalls);
            _output.WriteLine("Per call   : {0:F5} ms", sw.ElapsedMilliseconds / (float)numberOfPDPCalls);
            _output.WriteLine("Total PDP  : {0} ms", sw.ElapsedMilliseconds);
            _output.WriteLine("Total      : {0} ms\n", outer_sw.ElapsedMilliseconds);
            _output.WriteLine(string.Join("\n", results));
            _output.WriteLine("\nAll actions:");
            _output.WriteLine(string.Join("\n", actions));
            _output.WriteLine("\nAll tasks:");
            _output.WriteLine(string.Join("\n", tasks));

        }

        private static void SetContextRequestAction(XacmlContextRequest contextRequest, string action)
        {
            var actionCategory = new Uri(XacmlConstants.MatchAttributeCategory.Action);
            foreach (var attrs in contextRequest.Attributes)
            {
                if (!attrs.Category.Equals(actionCategory))
                {
                    continue;
                }

                foreach (var attr in attrs.Attributes)
                {
                    foreach (var value in attr.AttributeValues)
                    {
                        value.Value = action;
                    }
                }
            }
        }

        private static void SetContextRequestTask(XacmlContextRequest contextRequest, string task)
        {
            var actionCategory = new Uri(XacmlConstants.MatchAttributeCategory.Resource);
            var taskUri = new Uri("urn:altinn:task");
            foreach (var attrs in contextRequest.Attributes)
            {
                if (!attrs.Category.Equals(actionCategory))
                {
                    continue;
                }

                foreach (var attr in attrs.Attributes)
                {
                    if (!attr.AttributeId.Equals(taskUri))
                    {
                        continue;
                    }

                    foreach (var value in attr.AttributeValues)
                    {
                        value.Value = task;
                        return;
                    }
                }

                // No task attribute defined, add it
                var newAttr = new XacmlAttribute(taskUri, false);
                newAttr.AttributeValues.Add(new XacmlAttributeValue(new Uri("http://www.w3.org/2001/XMLSchema#string"))
                {
                    Value = task
                });
                attrs.Attributes.Add(newAttr);
            }
        }

        private XacmlContextResponse SetuUpPolicyDecisionPoint(string testCase, bool contextRequstIsEnriched)
        {
            XacmlContextRequest contextRequest = XacmlTestDataParser.ParseRequest(testCase + "Request.xml", GetAltinnAppsPath());
            XacmlContextRequest contextRequestEnriched = contextRequest;
            if (contextRequstIsEnriched)
            {
                contextRequestEnriched = XacmlTestDataParser.ParseRequest(testCase + "Request_Enriched.xml", GetAltinnAppsPath());
            }

            XacmlPolicy policy = XacmlTestDataParser.ParsePolicy(testCase + "Policy.xml", GetAltinnAppsPath());

            Moq.Mock<IContextHandler> moqContextHandler = new Mock<IContextHandler>();
            moqContextHandler.Setup(c => c.Enrich(It.IsAny<XacmlContextRequest>())).ReturnsAsync(contextRequestEnriched);

            PolicyDecisionPoint pdp = new PolicyDecisionPoint();

            XacmlContextResponse xacmlResponse = pdp.Authorize(contextRequestEnriched, policy);

            return xacmlResponse;
        }

        private string GetAltinnAppsPath()
        {
            string unitTestFolder = Path.GetDirectoryName(new Uri(typeof(AltinnAppsTests).Assembly.Location).LocalPath);
            return Path.Combine(unitTestFolder, @"..\..\..\Data\Xacml\3.0\AltinnApps");
        }
    }
}
