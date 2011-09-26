package net.schmizz.sshj.xfer.scp;

import net.schmizz.sshj.xfer.FileSystemFile;
import net.schmizz.sshj.xfer.LocalFileFilter;
import net.schmizz.sshj.xfer.LocalSourceFile;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.verification.VerificationMode;

import java.io.File;
import java.io.IOException;

import static org.mockito.Matchers.endsWith;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class SCPUploadClientTest {

	private SCPEngine engine;
	private SCPUploadClient scpUploadClient;

	@Rule
	public TemporaryFolder temp = new TemporaryFolder();

	@Before
	public void init() {
		engine = mock(SCPEngine.class);
		scpUploadClient = new SCPUploadClient(engine);
	}

	@Test
	public void shouldOnlySendFilterAcceptedFilesFromDirectory() throws IOException {
		scpUploadClient.setUploadFilter(new LocalFileFilter() {
			@Override
			public boolean accept(LocalSourceFile file) {
				return !file.getName().contains("not-");
			}
		});

		File dir = temp.newFolder("filtered-scp-upload");
		new File(dir, "not-sent.txt").createNewFile();
		new File(dir, "sent.txt").createNewFile();

		int copy = scpUploadClient.copy(new FileSystemFile(dir), "/tmp");
		verify(engine).startedDir("filtered-scp-upload");
		verify(engine).startedFile(eq("sent.txt"), isA(Long.class));
		verify(engine, times(1)).startedFile(isA(String.class), isA(Long.class));
	}
}
