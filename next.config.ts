import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Serve images (mostly static webp/png brand assets) as-is. The optimizer
  // rejects some of the supplied webp variants with a 400, so skip it.
  images: { unoptimized: true },
};

export default nextConfig;
