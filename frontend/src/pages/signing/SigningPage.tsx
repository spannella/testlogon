import { Link } from "react-router-dom";
import { FilePen, FilePlus2, Inbox, Send, LayoutTemplate } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SignatureTemplateManager } from "@/pages/signing/SignatureTemplateManager";

const HUB_LINKS = [
  {
    to: "/signing/new",
    title: "New request",
    desc: "Create and send a signature packet from a PDF.",
    icon: FilePlus2,
  },
  {
    to: "/signing/inbox",
    title: "Awaiting me",
    desc: "Documents waiting for your signature.",
    icon: Inbox,
  },
  {
    to: "/signing/inbox",
    title: "Sent",
    desc: "Track requests you've sent for signature.",
    icon: Send,
  },
];

export default function SigningPage() {
  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-2">
        <FilePen className="h-6 w-6" />
        <h1 className="text-xl font-semibold">Document Signing</h1>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {HUB_LINKS.map((link) => {
          const Icon = link.icon;
          return (
            <Link key={`${link.title}-${link.to}`} to={link.to} className="block">
              <Card className="h-full transition-colors hover:border-primary">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-base">
                    <Icon className="h-5 w-5 text-primary" /> {link.title}
                  </CardTitle>
                  <CardDescription>{link.desc}</CardDescription>
                </CardHeader>
              </Card>
            </Link>
          );
        })}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <LayoutTemplate className="h-5 w-5" /> Templates
          </CardTitle>
          <CardDescription>Manage reusable signature templates.</CardDescription>
        </CardHeader>
        <CardContent>
          <SignatureTemplateManager />
        </CardContent>
      </Card>
    </div>
  );
}
