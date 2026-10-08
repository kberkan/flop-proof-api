import type { Metadata } from "next";
import type { ReactNode } from "react";

// The page is a Client Component, which cannot export metadata; this layout carries its title.
// Absolute: the root template does not reach this segment through proofs/layout.tsx's plain title.
export async function generateMetadata({
  params,
}: {
  params: Promise<{ proof_id: string }>;
}): Promise<Metadata> {
  const { proof_id } = await params;
  return { title: { absolute: `Proof ${proof_id} · FLOP Proof Dashboard` } };
}

export default function Layout({ children }: { children: ReactNode }) {
  return children;
}
