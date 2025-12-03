/**
 * Pipeline Analysis Result Interface
 * 
 * Defines the structure for pipeline analysis job results returned by the service.
 * This interface is used throughout the system for type safety and clear contracts.
 * 
 * @see PIPELINE_ANALYZING_FEATURE_DECOMPOSITION_REFINED.md - TASK-001
 */
export interface PipelineAnalysisResult {
  success: boolean;
  jobId: string;
  message: string;
}









