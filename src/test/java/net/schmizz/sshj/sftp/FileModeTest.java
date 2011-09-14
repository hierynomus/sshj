package net.schmizz.sshj.sftp;

import org.junit.Test;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

public class FileModeTest {

	@Test
	public void shouldDetectDirectoryWithLinuxMask() {
		FileMode fileMode = new FileMode(040755);
		assertThat(fileMode.toString(), equalTo("[mask=40755]"));
		assertThat(fileMode.getType(), equalTo(FileMode.Type.DIRECTORY));
	}

	@Test
	public void shouldDetectDirectoryWithAixUnixMask() {
		FileMode fileMode = new FileMode(0240755);
		assertThat(fileMode.toString(), equalTo("[mask=240755]"));
		assertThat(fileMode.getType(), equalTo(FileMode.Type.DIRECTORY));
	}
}
