import { createFileRoute } from "@tanstack/react-router";
import { LegalPage, LegalSection } from "@/components/site/LegalPage";

export const Route = createFileRoute("/privacy")({
  head: () => ({
    meta: [
      { title: "Privacy Policy — GillNet AI" },
      {
        name: "description",
        content: "How GillNet AI collects, uses, and protects your data.",
      },
    ],
  }),
  component: Privacy,
});

function Privacy() {
  return (
    <LegalPage title="Privacy Policy" updated="9 October 2026">
      <p>
        GillNet AI ("we", "our") is an academic cybersecurity project developed at VIT Bhopal
        University. This policy explains what data we collect when you use the GillNet AI web
        application, and how we use and protect it.
      </p>

      <LegalSection heading="1. Data we collect">
        <p>
          <strong className="text-bright">Account data.</strong> When you sign in with Google, we
          receive your name, email address, and profile photo from Google OAuth. We store these to
          operate your account.
        </p>
        <p>
          <strong className="text-bright">Scan inputs.</strong> URLs, text, screenshots, and files
          you submit for analysis are sent to our servers so the detection engines can examine them.
          Scan records (the input, the result, and the time) are stored in your account history.
        </p>
        <p>
          <strong className="text-bright">Usage data.</strong> We track your credit balance and scan
          history to enforce the credit system (100 credits on registration, 50 replenished daily,
          one credit per successful scan).
        </p>
        <p>
          <strong className="text-bright">Technical data.</strong> Standard server logs (such as IP
          address, browser type, and request timestamps) may be collected for security and debugging.
          Your sign-in session token is stored in your browser's local storage.
        </p>
      </LegalSection>

      <LegalSection heading="2. How we use your data">
        <p>
          We use your data only to provide and improve the service: running phishing analyses,
          maintaining your account and credits, preventing abuse, and understanding aggregate usage
          patterns. We do not sell your personal data, and we do not share it with advertisers.
        </p>
      </LegalSection>

      <LegalSection heading="3. Data storage and security">
        <p>
          Data is stored in MongoDB Atlas with access restricted to the application backend. We apply
          reasonable technical safeguards, but no internet transmission or storage system can be
          guaranteed 100% secure.
        </p>
      </LegalSection>

      <LegalSection heading="4. Your rights">
        <p>
          You may request a copy of the data we hold about you, or ask us to delete your account and
          associated data, at any time. To make a request, contact the project team through your
          institution's project coordinator or the contact details provided in the application.
        </p>
      </LegalSection>

      <LegalSection heading="5. Children">
        <p>
          GillNet AI is not directed at children under 13, and we do not knowingly collect data from
          them.
        </p>
      </LegalSection>

      <LegalSection heading="6. Changes to this policy">
        <p>
          We may update this policy as the project evolves. The "Last updated" date above will always
          reflect the current version. Continued use of the service after changes means you accept the
          updated policy.
        </p>
      </LegalSection>
    </LegalPage>
  );
}
