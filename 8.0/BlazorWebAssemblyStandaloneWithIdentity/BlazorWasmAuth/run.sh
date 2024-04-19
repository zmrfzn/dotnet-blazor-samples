export NEW_RELIC_LICENSE_KEY=NEW_RELIC_LICENSE_KEY
export OTEL_EXPORTER_OTLP_HEADERS=api-key=${NEW_RELIC_LICENSE_KEY}
export OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp.nr-data.net
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_SERVICE_NAME=BlazorWASMStandaloneFrontend
export OTEL_RESOURCE_ATTRIBUTES=deployment.environment=staging,service.version=1.0.0
export DOTNET_RUNTIME_ID="linux-arm64"
export ENABLE_PROFILING=true
export OTEL_DOTNET_AUTO_HOME=$HOME/.otel-dotnet-auto
export CORECLR_ENABLE_PROFILING=1
export CORECLR_PROFILER="{918728DD-259F-4A6A-AC2B-B85E1B658318}"
# export DOTNET_RUNTIME_ID="osx-x64"
export SUFIX="dylib"
export CORECLR_PROFILER_PATH="$OTEL_DOTNET_AUTO_HOME/$DOTNET_RUNTIME_ID/OpenTelemetry.AutoInstrumentation.Native.$SUFIX"
dotnet run -lp https ./bin/Debug/net8.0/publish/BlazorWasmAuth
