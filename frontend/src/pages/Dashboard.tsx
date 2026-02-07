import { Sun, Moon, Monitor } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { useUiStore, type Theme } from "@/stores/uiStore";

const themes: { value: Theme; icon: React.ReactNode; label: string }[] = [
  { value: "light", icon: <Sun className="h-4 w-4" />, label: "Light" },
  { value: "dark", icon: <Moon className="h-4 w-4" />, label: "Dark" },
  { value: "system", icon: <Monitor className="h-4 w-4" />, label: "System" },
];

export default function Dashboard() {
  const theme = useUiStore((s) => s.theme);
  const setTheme = useUiStore((s) => s.setTheme);

  return (
    <div className="min-h-screen bg-background p-6 md:p-10">
      <div className="mx-auto max-w-5xl space-y-8">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Dashboard</h1>
          <p className="text-sm text-muted-foreground">
            Design system preview — full dashboard coming in Step 7
          </p>
        </div>

        {/* Theme toggle */}
        <Card>
          <CardHeader>
            <CardTitle>Theme</CardTitle>
            <CardDescription>Switch between light, dark, and system themes</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-2">
              {themes.map((t) => (
                <Button
                  key={t.value}
                  variant={theme === t.value ? "default" : "outline"}
                  size="sm"
                  onClick={() => setTheme(t.value)}
                >
                  {t.icon}
                  <span className="ml-1">{t.label}</span>
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Component showcase */}
        <div className="grid gap-6 md:grid-cols-2">
          {/* Buttons */}
          <Card>
            <CardHeader>
              <CardTitle>Buttons</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-2">
              <Button>Primary</Button>
              <Button variant="secondary">Secondary</Button>
              <Button variant="outline">Outline</Button>
              <Button variant="ghost">Ghost</Button>
              <Button variant="destructive">Destructive</Button>
              <Button variant="link">Link</Button>
              <Button disabled>Disabled</Button>
            </CardContent>
          </Card>

          {/* Badges */}
          <Card>
            <CardHeader>
              <CardTitle>Badges</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-2">
              <Badge>Default</Badge>
              <Badge variant="secondary">Secondary</Badge>
              <Badge variant="success">Success</Badge>
              <Badge variant="warning">Warning</Badge>
              <Badge variant="destructive">Destructive</Badge>
              <Badge variant="outline">Outline</Badge>
            </CardContent>
          </Card>

          {/* Inputs */}
          <Card>
            <CardHeader>
              <CardTitle>Inputs</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input id="email" type="email" placeholder="you@example.com" />
              </div>
              <div className="flex items-center gap-2">
                <Switch id="toggle" />
                <Label htmlFor="toggle">Enable notifications</Label>
              </div>
            </CardContent>
          </Card>

          {/* Skeleton loading */}
          <Card>
            <CardHeader>
              <CardTitle>Loading skeletons</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <Skeleton className="h-4 w-3/4" />
              <Skeleton className="h-4 w-1/2" />
              <Skeleton className="h-10 w-full" />
              <div className="flex items-center gap-3">
                <Skeleton className="h-10 w-10 rounded-full" />
                <div className="space-y-2 flex-1">
                  <Skeleton className="h-3 w-1/3" />
                  <Skeleton className="h-3 w-2/3" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <Separator />

        {/* Typography */}
        <Card>
          <CardHeader>
            <CardTitle>Typography</CardTitle>
            <CardDescription>Inter for UI text, JetBrains Mono for code</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-2xl font-semibold">Page title (24px semibold)</p>
            <p className="text-lg font-semibold">Section heading (18px semibold)</p>
            <p className="text-base font-medium">Card title (16px medium)</p>
            <p className="text-sm">Body text (14px regular)</p>
            <p className="text-xs font-medium text-muted-foreground">
              Caption / label (12px medium, muted)
            </p>
            <p className="font-mono text-sm">Monospace: API_KEY_abc123xyz</p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
