"use client";

// Burhan app shell — sidebar + topbar + mobile drawer + auth guard.
// RTL-aware via logical utilities; keyboard accessible; reduced-motion safe.

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import {
  Activity,
  Building2,
  FileText,
  Globe,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Network,
  Radar,
  ScrollText,
  Search,
  Sun,
  Target,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Separator } from "@/components/ui/separator";
import { useI18n, type DictKey } from "@/lib/ui/i18n";
import { useTheme } from "@/lib/ui/theme";
import { useSession } from "@/lib/ui/session";
import { useToast } from "@/lib/ui/toast";

function BrandMark({ className = "size-8" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden focusable="false">
      <path
        d="M16 2.5 27 7v9.2c0 6.6-4.4 11.6-11 13.3-6.6-1.7-11-6.7-11-13.3V7l11-4.5Z"
        className="fill-primary/15 stroke-primary"
        strokeWidth="1.6"
      />
      <path
        d="M9.5 16.5h4l2-5 3 9 2-4h4"
        fill="none"
        className="stroke-primary"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

type NavItem = { key: DictKey; href: string; icon: React.ReactNode; exact?: boolean };
const MAIN: NavItem[] = [
  { key: "nav.overview", href: "/overview", icon: <LayoutDashboard className="size-4" aria-hidden />, exact: true },
  { key: "nav.targets", href: "/targets", icon: <Target className="size-4" aria-hidden /> },
  { key: "nav.scans", href: "/scans", icon: <Radar className="size-4" aria-hidden /> },
  { key: "nav.findings", href: "/findings", icon: <Activity className="size-4" aria-hidden /> },
  { key: "nav.reports", href: "/reports", icon: <FileText className="size-4" aria-hidden /> },
  { key: "nav.twin", href: "/twin", icon: <Network className="size-4" aria-hidden /> },
];
const GOV: NavItem[] = [
  { key: "nav.organization", href: "/organization", icon: <Building2 className="size-4" aria-hidden /> },
  { key: "nav.audit", href: "/audit", icon: <ScrollText className="size-4" aria-hidden /> },
];

function isActive(pathname: string, item: NavItem): boolean {
  return item.exact ? pathname === item.href : pathname === item.href || pathname.startsWith(item.href + "/");
}

function NavLinks({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();
  const { t } = useI18n();
  const groups: Array<{ labelKey: DictKey; items: NavItem[] }> = [
    { labelKey: "nav.section.main", items: MAIN },
    { labelKey: "nav.section.governance", items: GOV },
  ];
  return (
    <nav aria-label="main navigation" className="flex flex-col gap-5 px-3 py-4">
      {groups.map((g) => (
        <div key={g.labelKey}>
          <p className="mb-1.5 px-2.5 text-[11px] font-bold uppercase tracking-wider text-muted-foreground/70">
            {t(g.labelKey)}
          </p>
          <ul className="space-y-0.5">
            {g.items.map((item) => {
              const active = isActive(pathname, item);
              return (
                <li key={item.href} className="relative">
                  {active ? (
                    <span
                      aria-hidden
                      className="absolute inset-y-1.5 -start-3 w-[3px] rounded-full bg-primary"
                    />
                  ) : null}
                  <Link
                    href={item.href}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    className={
                      "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm font-semibold outline-offset-2 transition-colors duration-150 " +
                      (active
                        ? "bg-[color-mix(in_oklab,var(--primary)_14%,transparent)] text-[color-mix(in_oklab,var(--primary)_78%,var(--foreground))]"
                        : "text-muted-foreground hover:bg-muted hover:text-foreground")
                    }
                  >
                    {item.icon}
                    <span className="flex-1">{t(item.key)}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function SidebarInner({ onNavigate }: { onNavigate?: () => void }) {
  const { t } = useI18n();
  return (
    <div className="flex h-full flex-col">
      <Link href="/overview" className="focus-visible:outline-offset-4">
        <div className="flex items-center gap-2.5 border-b px-5 py-4">
          <BrandMark />
          <div className="leading-tight">
            <p className="text-base font-extrabold tracking-tight">{t("brand.name")}</p>
            <p className="text-[11px] font-medium text-muted-foreground">{t("brand.tagline")}</p>
          </div>
        </div>
      </Link>
      <div className="min-h-0 flex-1 overflow-y-auto">
        <NavLinks onNavigate={onNavigate} />
      </div>
      <div className="border-t px-5 py-3">
        <p className="text-[11px] leading-5 text-muted-foreground/80">
          {t("brand.name")} · <span className="num">v4.1.1</span>
        </p>
      </div>
    </div>
  );
}

function Topbar({ onOpenMobile, onOpenPalette }: { onOpenMobile: () => void; onOpenPalette: () => void }) {
  const { t, locale, setLocale } = useI18n();
  const { theme, toggle } = useTheme();
  const session = useSession();
  const toast = useToast();
  const user = session.me?.user;
  const org = session.org;
  const initials = (user?.name || user?.email || "?").trim().slice(0, 2).toUpperCase();
  const isMac =
    typeof navigator !== "undefined" && /Mac|iPhone|iPad|iPod/.test(navigator.platform || navigator.userAgent);

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b bg-[color-mix(in_oklab,var(--background)_86%,transparent)] px-3 backdrop-blur-sm sm:px-5">
      <Button
        variant="ghost"
        size="icon"
        className="size-9 lg:hidden"
        onClick={onOpenMobile}
        aria-label="open navigation menu"
      >
        <Menu className="size-5" aria-hidden />
      </Button>

      <div className="hidden min-w-0 sm:block">
        <p className="truncate text-sm font-bold leading-5">{org?.name ?? t("shell.org")}</p>
        <p className="truncate text-[11px] leading-4 text-muted-foreground">
          {t(`shell.role.${session.role.toLowerCase()}` as never)}
          {org
            ? ` · ${org.counts.targets} ${t("overview.kpi.targets")} · ${org.counts.scans} ${t("overview.kpi.scans")}`
            : ""}
        </p>
      </div>

      <div className="ms-auto flex items-center gap-1">
        <Button
          variant="ghost"
          className="hidden h-9 gap-2 px-2.5 lg:inline-flex"
          onClick={onOpenPalette}
          aria-label={t("palette.open")}
          title={t("palette.open")}
        >
          <Search className="size-4" aria-hidden />
          <kbd className="num pointer-events-none rounded border bg-muted px-1.5 py-0.5 text-[10px] font-bold text-muted-foreground">
            {isMac ? "⌘K" : "Ctrl K"}
          </kbd>
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="size-9"
          onClick={toggle}
          aria-label={theme === "dark" ? t("theme.toLight") : t("theme.toDark")}
          title={theme === "dark" ? t("theme.toLight") : t("theme.toDark")}
        >
          {theme === "dark" ? <Sun className="size-4" aria-hidden /> : <Moon className="size-4" aria-hidden />}
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="size-9"
          onClick={() => setLocale(locale === "ar" ? "en" : "ar")}
          aria-label={t("locale.switch")}
          title={t("locale.switch")}
        >
          <Globe className="size-4.5" aria-hidden />
        </Button>
        <Separator orientation="vertical" className="mx-1 hidden h-6 sm:inline-flex" />
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="h-9 gap-2 px-1.5" aria-label="user menu">
              <Avatar className="size-7">
                <AvatarFallback className="text-[11px] font-bold">{initials}</AvatarFallback>
              </Avatar>
              <span className="hidden max-w-28 truncate text-sm font-semibold md:inline">
                {user?.name || user?.email}
              </span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel className="leading-tight">
              <p className="text-sm font-bold">{user?.name || "—"}</p>
              <p className="text-xs font-normal text-muted-foreground">{user?.email}</p>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => {
                void session.signOut().then(() => toast.info(t("user.signedOut")));
              }}
              className="text-[var(--severity-critical)] focus:text-[var(--severity-critical)]"
            >
              <LogOut className="size-4" aria-hidden />
              {t("user.signOut")}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const { t, dir } = useI18n();
  const session = useSession();
  const router = useRouter();
  const [navOpen, setNavOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);

  // FG-2: global Ctrl+K (desktop) / ⌘K (Mac) command palette toggle.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // auth guard (UX layer — the API layer remains the enforcement point)
  useEffect(() => {
    if (session.ready && !session.me) router.replace("/login");
  }, [session.ready, session.me, router]);

  if (!session.ready || !session.me) {
    return (
      <div className="flex min-h-dvh items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-3" role="status" aria-live="polite">
          <BrandMark className="size-12" />
          <p className="text-sm font-semibold text-muted-foreground">{t("common.loading")}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-dvh bg-background">
      <a
        href="#content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:z-50 focus:rounded focus:bg-primary focus:px-3 focus:py-1.5 focus:text-sm focus:font-bold focus:text-primary-foreground"
      >
        {t("shell.skipToContent")}
      </a>
      <div className="flex min-h-dvh">
        <aside className="sticky top-0 hidden h-dvh w-60 shrink-0 border-e bg-sidebar text-sidebar-foreground lg:block">
          <SidebarInner />
        </aside>
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar onOpenMobile={() => setNavOpen(true)} onOpenPalette={() => setPaletteOpen(true)} />
          <main id="content" className="flex-1 px-3 py-5 sm:px-6 lg:px-8">
            <div className="mx-auto w-full max-w-6xl">{children}</div>
          </main>
        </div>
      </div>

      {/* FG-3: SheetTitle + SheetDescription (sr-only) — no Radix a11y warning */}
      <Sheet open={navOpen} onOpenChange={setNavOpen}>
        <SheetContent side={dir === "rtl" ? "right" : "left"} className="w-64 p-0" aria-label={t("shell.nav")}>
          <SheetTitle className="sr-only">{t("shell.nav")}</SheetTitle>
          <SheetDescription className="sr-only">{t("shell.navDesc")}</SheetDescription>
          <SidebarInner onNavigate={() => setNavOpen(false)} />
        </SheetContent>
      </Sheet>

      {/* FG-2: command palette — navigation to REAL existing routes only */}
      <CommandDialog
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        dir={dir}
        title={t("palette.title")}
        description={t("palette.placeholder")}
      >
        <CommandInput placeholder={t("palette.placeholder")} />
        <CommandList>
          <CommandEmpty>{t("palette.empty")}</CommandEmpty>
          <CommandGroup heading={t("nav.section.main")}>
            {MAIN.map((item) => (
              <CommandItem
                key={item.href}
                value={`${t(item.key)} ${item.href}`}
                onSelect={() => {
                  setPaletteOpen(false);
                  router.push(item.href);
                }}
              >
                {item.icon}
                {t(item.key)}
              </CommandItem>
            ))}
          </CommandGroup>
          <CommandGroup heading={t("nav.section.governance")}>
            {GOV.map((item) => (
              <CommandItem
                key={item.href}
                value={`${t(item.key)} ${item.href}`}
                onSelect={() => {
                  setPaletteOpen(false);
                  router.push(item.href);
                }}
              >
                {item.icon}
                {t(item.key)}
              </CommandItem>
            ))}
          </CommandGroup>
        </CommandList>
      </CommandDialog>
    </div>
  );
}
