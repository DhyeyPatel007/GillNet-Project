import { createFileRoute } from "@tanstack/react-router";
import { LegalPage, LegalSection } from "@/components/site/LegalPage";

export const Route = createFileRoute("/terms")({
  head: () => ({
    meta: [
      { title: "Terms of Service — GillNet AI" },
      {
        name: "description",
        content: "The terms governing your use of GillNet AI.",
      },
    ],
  }),
  component: Terms,
});

function Terms() {
  return (
    <LegalPage title="Terms of Service" updated="9 October 2026">
      <p>
        Welcome to GillNet AI, an academic cybersecurity project developed at VIT Bhopal University.
        By creating an account or using the service, you agree to these terms.
      </p>

      <LegalSection heading="1. The service">
        <p>
          GillNet AI provides heuristic phishing-detection tools: a link scanner, a message/text
          scanner, a screenshot analyzer, and a file-forensics ("Autopsy") module. The service is
          provided for educational and research purposes.
        </p>
      </LegalSection>

      <LegalSection heading="2. Accounts and credits">
        <p>
          You must sign in with a Google account to use the scanners. New accounts receive 100
          credits, with 50 credits replenished once per day. Each successful scan costs one credit;
          failed scans are not charged. Credits have no monetary value and cannot be transferred or
          redeemed.
        </p>
      </LegalSection>

      <LegalSection heading="3. Acceptable use">
        <p>You agree not to:</p>
        <ul className="list-disc pl-6 space-y-1">
          <li>Use the service to analyze data you have no right to examine.</li>
          <li>Attempt to disrupt, overload, or reverse-engineer the service.</li>
          <li>Circumvent the credit system or access controls.</li>
          <li>Submit malicious content intended to harm the service or other users.</li>
        </ul>
        <p>We may suspend accounts that abuse the service.</p>
      </LegalSection>

      <LegalSection heading="4. Important disclaimer">
        <p>
          GillNet AI uses a heuristic, rule-based detection engine. Results are estimates produced
          for educational purposes — they are not guarantees. A "safe" result does not mean a link,
          message, or file is harmless, and a "phishing" result is not proof of malicious intent.
          Always exercise your own judgment, keep your software updated, and never enter sensitive
          credentials on sites you do not fully trust. We are not liable for decisions you make based
          on scan results.
        </p>
      </LegalSection>

      <LegalSection heading="5. Intellectual property">
        <p>
          The GillNet AI application, including its detection engine, interface, and content, is the
          work of its student developers. You retain ownership of the files and text you submit for
          analysis.
        </p>
      </LegalSection>

      <LegalSection heading="6. Service availability">
        <p>
          As an academic project, the service is provided "as is" without warranties of any kind, and
          may be modified, suspended, or discontinued at any time.
        </p>
      </LegalSection>

      <LegalSection heading="7. Changes to these terms">
        <p>
          We may update these terms as the project evolves. The "Last updated" date above will always
          reflect the current version. Continued use of the service after changes means you accept the
          updated terms.
        </p>
      </LegalSection>
    </LegalPage>
  );
}
