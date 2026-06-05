import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { getScans, getScanDetail, getStats, createScan, getLLMAnalysis } from "./client"
import type { ScanSummary, ScanDetail, DashboardStats } from "./types"

export function useScans() {
  return useQuery<ScanSummary[]>({
    queryKey: ["scans"],
    queryFn: getScans,
  })
}

export function useScanDetail(id: string) {
  return useQuery<ScanDetail>({
    queryKey: ["scan", id],
    queryFn: () => getScanDetail(id),
    enabled: !!id,
  })
}

export function useStats() {
  return useQuery<DashboardStats>({
    queryKey: ["stats"],
    queryFn: getStats,
  })
}

export function useCreateScan() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: createScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] })
      queryClient.invalidateQueries({ queryKey: ["stats"] })
    },
  })
}

export function useLLMAnalysis() {
  return useMutation({
    mutationFn: getLLMAnalysis,
  })
}
