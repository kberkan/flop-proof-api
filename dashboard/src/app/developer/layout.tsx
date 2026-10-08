import type { Metadata } from "next";
import type { ReactNode } from "react";

// The page is a Client Component, which cannot export metadata; this layout carries its title.
export const metadata: Metadata = { title: "Developer" };

export default function Layout({ children }: { children: ReactNode }) {
  return children;
}
